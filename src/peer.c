#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// ---------------------------
// Globals
// ---------------------------
NetworkAddress_t *my_address = NULL;

#define MAX_PEERS 128
NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

// ---------------------------
// Thread-safe printing
// ---------------------------
void ts_print(const char *fmt, ...)
{
    pthread_mutex_lock(&print_mutex);

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fflush(stdout);

    pthread_mutex_unlock(&print_mutex);
}

// ---------------------------
// Validation helper
// ---------------------------
int error_helper(char *ip, int port)
{
    if (!is_valid_ip(ip))
    {
        fprintf(stderr, ">> Invalid peer IP: %s\n", ip);
        return 0;
    }
    if (!is_valid_port(port))
    {
        fprintf(stderr, ">> Invalid peer port: %d\n", port);
        return 0;
    }
    return 1;
}

// ---------------------------
// Signature helpers
// ---------------------------
void get_signature(void *password, int password_len, char *salt, hashdata_t *out_hash)
{
    int combined_len = password_len + SALT_LEN;
    char *buf = malloc(combined_len);
    if (!buf)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    memcpy(buf, password, password_len);
    memcpy(buf + password_len, salt, SALT_LEN);

    get_data_sha(buf, *out_hash, (uint32_t)combined_len, SHA256_HASH_SIZE);

    memset(buf, 0, combined_len);
    free(buf);
}

void compute_final_signature(hashdata_t client_sig, char *salt, hashdata_t *out)
{
    get_signature(client_sig, SHA256_HASH_SIZE, salt, out);
}

// ---------------------------
// Network list management
// ---------------------------

/*
 * Unified helper:
 * - if candidate already exists: returns existing pointer, sets *added=0
 * - otherwise allocates/copies, appends, returns new pointer, sets *added=1
 */
NetworkAddress_t *get_or_add_peer(const NetworkAddress_t *candidate, int *added)
{
    pthread_mutex_lock(&network_mutex);

    // already present?
    for (uint32_t i = 0; i < peer_count; i++)
    {
        if (strcmp(network[i]->ip, candidate->ip) == 0 &&
            network[i]->port == candidate->port)
        {
            if (added) *added = 0;
            NetworkAddress_t *existing = network[i];
            pthread_mutex_unlock(&network_mutex);
            return existing;
        }
    }

    // capacity check
    if (peer_count >= MAX_PEERS)
    {
        ts_print(">> Network full, cannot add more peers.\n");
        if (added) *added = 0;
        pthread_mutex_unlock(&network_mutex);
        return NULL;
    }

    NetworkAddress_t *new_peer = malloc(sizeof(NetworkAddress_t));
    if (!new_peer)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(new_peer, candidate, sizeof(NetworkAddress_t));
    network[peer_count++] = new_peer;

    if (added) *added = 1;

    pthread_mutex_unlock(&network_mutex);
    return new_peer;
}

// Return a random peer that is not 'self'. NULL if none.
NetworkAddress_t *get_random_peer(const NetworkAddress_t *self)
{
    pthread_mutex_lock(&network_mutex);

    if (peer_count <= 1)
    {
        pthread_mutex_unlock(&network_mutex);
        return NULL;
    }

    NetworkAddress_t *eligible[MAX_PEERS];
    uint32_t eligible_count = 0;

    for (uint32_t i = 0; i < peer_count; i++)
    {
        NetworkAddress_t *p = network[i];
        if (strcmp(p->ip, self->ip) != 0 || p->port != self->port)
        {
            eligible[eligible_count++] = p;
        }
    }

    if (eligible_count == 0)
    {
        pthread_mutex_unlock(&network_mutex);
        return NULL;
    }

    uint32_t index = rand() % eligible_count;
    NetworkAddress_t *chosen = eligible[index];

    pthread_mutex_unlock(&network_mutex);
    return chosen;
}

void free_network()
{
    pthread_mutex_lock(&network_mutex);

    for (uint32_t i = 0; i < peer_count; i++)
    {
        // don't double free my_address if it's in list
        if (network[i] != my_address)
            free(network[i]);
    }
    free(network);

    peer_count = 0;
    network = NULL;

    pthread_mutex_unlock(&network_mutex);
}

// ---------------------------
// Messaging
// ---------------------------
int send_message(NetworkAddress_t *peer, int command, void *body, size_t body_len)
{
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", peer->port);

    int sock = compsys_helper_open_clientfd(peer->ip, port_str);
    if (sock < 0)
    {
        fprintf(stderr, "Could not connect to %s:%d\n", peer->ip, peer->port);
        return -1;
    }

    RequestHeader_t req;
    memset(&req, 0, sizeof(req));

    strncpy(req.ip, my_address->ip, IP_LEN - 1);
    req.ip[IP_LEN - 1] = '\0';

    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(command);
    req.length = htonl((uint32_t)body_len);

    if (compsys_helper_writen(sock, &req, sizeof(req)) != (ssize_t)sizeof(req))
    {
        perror("send header");
        close(sock);
        return -1;
    }

    if (body_len > 0 && body != NULL)
    {
        if (compsys_helper_writen(sock, body, body_len) != (ssize_t)body_len)
        {
            perror("send body");
            close(sock);
            return -1;
        }
    }

    // ----- REGISTER reply -----
    if (command == COMMAND_REGISTER)
    {
        ReplyHeader_t reply;
        if (compsys_helper_readn(sock, &reply, sizeof(reply)) != (ssize_t)sizeof(reply))
        {
            fprintf(stderr, "Failed to read REGISTER reply header\n");
            close(sock);
            return -1;
        }

        uint32_t reply_length = ntohl(reply.length);
        uint32_t reply_status = ntohl(reply.status);

        if (reply_status != STATUS_OK)
        {
            fprintf(stderr, "Register failed (status=%u)\n", reply_status);
            close(sock);
            return -1;
        }

        if (reply_length % sizeof(NetworkAddress_t) != 0)
        {
            fprintf(stderr, "REGISTER reply malformed length=%u\n", reply_length);
            close(sock);
            return -1;
        }

        char *reply_body = malloc(reply_length);
        if (!reply_body)
        {
            perror("malloc");
            close(sock);
            return -1;
        }

        if (compsys_helper_readn(sock, reply_body, reply_length) != (ssize_t)reply_length)
        {
            fprintf(stderr, "Failed to read REGISTER reply body\n");
            free(reply_body);
            close(sock);
            return -1;
        }

        int peers_in_msg = reply_length / sizeof(NetworkAddress_t);
        for (int i = 0; i < peers_in_msg; i++)
        {
            NetworkAddress_t *candidate =
                (NetworkAddress_t *)(reply_body + i * sizeof(NetworkAddress_t));
            int added;
            get_or_add_peer(candidate, &added);
        }

        free(reply_body);
        close(sock);
        return 0;
    }

    // ----- RETREIVE reply -----
    if (command == COMMAND_RETREIVE)
    {
        char local_name[FILENAME_MAX];
        memset(local_name, 0, sizeof(local_name));

        if (body_len >= FILENAME_MAX) body_len = FILENAME_MAX - 1;
        memcpy(local_name, (const char *)body, body_len);
        local_name[body_len] = '\0';

        FILE *fp = fopen(local_name, "wb");
        if (!fp)
        {
            perror("fopen");
            close(sock);
            return -1;
        }

        compsys_helper_state_t rio;
        compsys_helper_readinitb(&rio, sock);

        uint32_t total_bytes = 0;
        uint8_t expected_total_hash[SHA256_HASH_SIZE];

        while (1)
        {
            ReplyHeader_t reply;
            if (compsys_helper_readnb(&rio, &reply, sizeof(reply)) != (ssize_t)sizeof(reply))
            {
                fprintf(stderr, "Failed to read file reply header\n");
                fclose(fp);
                close(sock);
                return -1;
            }

            uint32_t block_len = ntohl(reply.length);
            uint32_t status = ntohl(reply.status);
            uint32_t block_num = ntohl(reply.this_block);
            uint32_t total_blocks= ntohl(reply.block_count);

            uint8_t block_hash[SHA256_HASH_SIZE];
            uint8_t total_hash[SHA256_HASH_SIZE];

            memcpy(block_hash, reply.block_hash, SHA256_HASH_SIZE);
            memcpy(total_hash, reply.total_hash, SHA256_HASH_SIZE);

            if (status == STATUS_DONE)
            {
                ts_print("File transfer complete. Total bytes=%u\n", total_bytes);
                
                uint8_t file_hash[SHA256_HASH_SIZE];
                fseek(fp, 0, SEEK_SET);
                char *file_buf = malloc(total_bytes);
                if (file_buf)
                {
                    fread(file_buf, 1, total_bytes, fp);
                    get_data_sha(file_buf, file_hash, total_bytes, SHA256_HASH_SIZE);
                    if (memcmp(file_hash, total_hash, SHA256_HASH_SIZE) != 0)
                        fprintf(stderr, "WARNING: Total file hash mismatch!\n");
                    free(file_buf);
                }
                
                fclose(fp);
                close(sock);
                return 0;
            }

            if (status != STATUS_OK)
            {
                fprintf(stderr, "File transfer failed (status=%u)\n", status);
                fclose(fp);
                close(sock);
                return -1;
            }

            if (block_len > FILE_BLOCK_SIZE)
            {
                fprintf(stderr, "Block length too large (%u)\n", block_len);
                fclose(fp);
                close(sock);
                return -1;
            }

            char buffer[FILE_BLOCK_SIZE];
            if (compsys_helper_readnb(&rio, buffer, block_len) != (ssize_t)block_len)
            {
                fprintf(stderr, "Failed to read block %u data\n", block_num);
                fclose(fp);
                close(sock);
                return -1;
            }
            
            uint8_t block_hash_check[SHA256_HASH_SIZE];
            get_data_sha(buffer, block_hash_check, block_len, SHA256_HASH_SIZE);
            if (memcmp(block_hash_check, block_hash, SHA256_HASH_SIZE) != 0)
            {
                fprintf(stderr, "WARNING: Block %u hash mismatch!\n", block_num);
            }

            fwrite(buffer, 1, block_len, fp);
            total_bytes += block_len;
        }
    }

    close(sock);
    return 0;
}

// ---------------------------
// Inform peers about new peer
// ---------------------------
void inform_all_other_peers(NetworkAddress_t *new_peer)
{
    NetworkAddress_t *local_copy[MAX_PEERS];
    uint32_t local_count = 0;

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++)
    {
        NetworkAddress_t *p = network[i];
        if (p != my_address &&
            !(strcmp(p->ip, new_peer->ip) == 0 && p->port == new_peer->port))
        {
            local_copy[local_count++] = p;
        }
    }
    pthread_mutex_unlock(&network_mutex);

    for (uint32_t i = 0; i < local_count; i++)
    {
        send_message(local_copy[i], COMMAND_INFORM, new_peer, sizeof(NetworkAddress_t));
    }
}

// ---------------------------
// Server request thread
// ---------------------------
void *handle_server_request_thread(void *arg)
{
    pthread_detach(pthread_self());

    int connfd = *((int *)arg);
    free(arg);

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, connfd);

    RequestHeader_t req;
    if (compsys_helper_readnb(&rio, &req, sizeof(req)) != (ssize_t)sizeof(req))
    {
        fprintf(stderr, ">> [Server] Failed to read request header\n");
        close(connfd);
        return NULL;
    }

    uint32_t command  = ntohl(req.command);
    uint32_t body_len = ntohl(req.length);
    uint32_t port     = ntohl(req.port);

    ts_print(">> [Server] Received command=%u length=%u from %s:%u\n",
             command, body_len, req.ip, port);

    // ===== INFORM =====
    if (command == COMMAND_INFORM)
    {
        NetworkAddress_t new_peer;
        if (compsys_helper_readnb(&rio, &new_peer, sizeof(new_peer)) != (ssize_t)sizeof(new_peer))
        {
            fprintf(stderr, ">> [Server] Failed to read INFORM body\n");
            close(connfd);
            return NULL;
        }

        int added;
        get_or_add_peer(&new_peer, &added);

        ts_print("Server list is now:\n");
        pthread_mutex_lock(&network_mutex);
        for (uint32_t i = 0; i < peer_count; i++)
        {
            ts_print(" - %s:%d\n", network[i]->ip, network[i]->port);
        }
        pthread_mutex_unlock(&network_mutex);

        close(connfd);
        return NULL;
    }

    // ===== REGISTER =====
    if (command == COMMAND_REGISTER)
    {
        if (!error_helper(req.ip, (int)port))
        {
            ReplyHeader_t reply = {
                .length = htonl(0),
                .status = htonl(STATUS_MALFORMED),
                .this_block = htonl(0)
            };
            compsys_helper_writen(connfd, &reply, sizeof(reply));
            close(connfd);
            return NULL;
        }

        NetworkAddress_t candidate;
        memset(&candidate, 0, sizeof(candidate));
        memcpy(candidate.ip, req.ip, IP_LEN);
        candidate.port = port;

        int added_flag = 0;
        NetworkAddress_t *peer = get_or_add_peer(&candidate, &added_flag);

        if (!peer)
        {
            ReplyHeader_t reply = {
                .length = htonl(0),
                .status = htonl(STATUS_MALFORMED),
                .this_block = htonl(0)
            };
            compsys_helper_writen(connfd, &reply, sizeof(reply));
            close(connfd);
            return NULL;
        }

        if (added_flag)
        {
            generate_random_salt(peer->salt);
            get_signature(req.signature, SHA256_HASH_SIZE, peer->salt, &peer->signature);
            inform_all_other_peers(peer);
        }
        else
        {
            hashdata_t test_final;
            compute_final_signature(req.signature, peer->salt, &test_final);

            if (memcmp(test_final, peer->signature, SHA256_HASH_SIZE) != 0)
            {
                ReplyHeader_t reply = {
                    .length = htonl(0),
                    .status = htonl(STATUS_BAD_PASSWORD),
                    .this_block = htonl(0)
                };
                compsys_helper_writen(connfd, &reply, sizeof(reply));
                close(connfd);
                return NULL;
            }
        }

        uint32_t body_size = peer_count * sizeof(NetworkAddress_t);
        char *reply_body = malloc(body_size);
        if (!reply_body)
        {
            perror("malloc");
            close(connfd);
            return NULL;
        }

        pthread_mutex_lock(&network_mutex);
        for (uint32_t i = 0; i < peer_count; i++)
        {
            memcpy(reply_body + i * sizeof(NetworkAddress_t),
                   network[i], sizeof(NetworkAddress_t));
        }
        pthread_mutex_unlock(&network_mutex);

        ReplyHeader_t reply = {
            .length = htonl(body_size),
            .status = htonl(STATUS_OK),
            .this_block = htonl(0)
        };

        compsys_helper_writen(connfd, &reply, sizeof(reply));
        compsys_helper_writen(connfd, reply_body, body_size);

        free(reply_body);
        close(connfd);
        return NULL;
    }

    // ===== GET_FILE / RETREIVE =====
    if (command == COMMAND_RETREIVE)
    {
        if (body_len == 0 || body_len >= FILENAME_MAX)
        {
            fprintf(stderr, ">> [Server] Invalid filename length %u\n", body_len);
            close(connfd);
            return NULL;
        }

        char filename[FILENAME_MAX];
        memset(filename, 0, sizeof(filename));

        if (compsys_helper_readnb(&rio, filename, body_len) != (ssize_t)body_len)
        {
            fprintf(stderr, ">> [Server] Failed to read filename\n");
            close(connfd);
            return NULL;
        }

        filename[body_len] = '\0';
        filename[strcspn(filename, "\r\n")] = '\0';

        ts_print(">> [Server] Client requested file: '%s'\n", filename);

        FILE *fp = fopen(filename, "rb");
        if (!fp)
        {
            ReplyHeader_t reply = {
                .length = htonl(0),
                .status = htonl(STATUS_FILE_NOT_FOUND),
                .this_block = htonl(0)
            };
            compsys_helper_writen(connfd, &reply, sizeof(reply));
            close(connfd);
            return NULL;
        }

        // Calculate file size and block count
        fseek(fp, 0, SEEK_END);
        long filesize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        uint32_t total_blocks = (filesize + FILE_BLOCK_SIZE - 1) / FILE_BLOCK_SIZE;

        // Compute total file hash
        uint8_t total_hash[SHA256_HASH_SIZE];
        get_file_sha(filename, total_hash, SHA256_HASH_SIZE);

        char buffer[FILE_BLOCK_SIZE];
        uint32_t block_number = 0;
        size_t bytes_read;

        while ((bytes_read = fread(buffer, 1, FILE_BLOCK_SIZE, fp)) > 0)
        {
            uint8_t block_hash[SHA256_HASH_SIZE];
            get_data_sha(buffer, block_hash, bytes_read, SHA256_HASH_SIZE);

            ReplyHeader_t reply;
            memset(&reply, 0, sizeof(reply));
            reply.length      = htonl((uint32_t)bytes_read);
            reply.status      = htonl(STATUS_OK);
            reply.this_block  = htonl(block_number);
            reply.block_count = htonl(total_blocks);
            memcpy(reply.block_hash, block_hash, SHA256_HASH_SIZE);
            memcpy(reply.total_hash, total_hash, SHA256_HASH_SIZE);

            compsys_helper_writen(connfd, &reply, sizeof(reply));
            compsys_helper_writen(connfd, buffer, bytes_read);
            block_number++;
        }

        ReplyHeader_t end = {
            .length = htonl(0),
            .status = htonl(STATUS_DONE),
            .this_block = htonl(block_number)
        };
        compsys_helper_writen(connfd, &end, sizeof(end));

        fclose(fp);
        ts_print(">> [Server] Sent file '%s' in %u blocks\n", filename, block_number);

        close(connfd);
        return NULL;
    }

    close(connfd);
    return NULL;
}

// ---------------------------
// Client thread
// ---------------------------
void *client_thread()
{
    
    while (1)
    {
        char peer_ip[IP_LEN];
        fprintf(stdout, "Enter peer IP to connect to: ");
        if (!fgets(peer_ip, sizeof(peer_ip), stdin)) continue;
        peer_ip[strcspn(peer_ip, "\n")] = '\0';

        if (!is_valid_ip(peer_ip))
        {
            printf("Invalid ip, try again\n");
            continue;
        }

        char peer_port[PORT_STR_LEN];
        fprintf(stdout, "Enter peer port to connect to: ");
        if (!fgets(peer_port, sizeof(peer_port), stdin)) continue;
        peer_port[strcspn(peer_port, "\n")] = '\0';

        if (!is_valid_port(atoi(peer_port)))
        {
            printf("Invalid port, try again\n");
            continue;
        }

        NetworkAddress_t peer_address;
        memset(&peer_address, 0, sizeof(peer_address));
        memcpy(peer_address.ip, peer_ip, IP_LEN);
        peer_address.port = atoi(peer_port);

        if (send_message(&peer_address, COMMAND_REGISTER, NULL, 0) == -1)
        {
            printf("connection failed\n");
            continue;
        }
        printf("\nKnown peers after registration:\n");
            pthread_mutex_lock(&network_mutex);
            for (uint32_t i = 0; i < peer_count; i++)
                printf(" - %s:%d\n", network[i]->ip, network[i]->port);
            pthread_mutex_unlock(&network_mutex);

        while(1)
        {
            
            char filename[FILENAME_MAX];
            printf("Please enter a file name: ");
            fflush(stdout);
            if (!fgets(filename, sizeof(filename), stdin))
            {
                fprintf(stderr, "Error reading input.\n");
                continue;
            }
            filename[strcspn(filename, "\r\n")] = '\0';

            if (strlen(filename) == 0) continue;

            printf("Requesting file: '%s'\n", filename);

            size_t filename_len = strlen(filename);

            NetworkAddress_t *target = get_random_peer(my_address);
            if (target == NULL)
            {
                fprintf(stderr, ">> [Client] No available peers to request file from\n");
            }

            if(send_message(target, COMMAND_RETREIVE, filename, filename_len)!=0){
                printf("Transfer failed, try agian\n");
                continue;
            }
        }
    }
        

    return NULL;
}

// ---------------------------
// Server thread
// ---------------------------
void *server_thread(void *unused)
{
    (void)unused;

    char port_str[PORT_STR_LEN];
    snprintf(port_str, sizeof(port_str), "%d", my_address->port);

    int listenfd = compsys_helper_open_listenfd(port_str);
    if (listenfd < 0)
    {
        fprintf(stderr, ">> Failed to open listen socket on port %s\n", port_str);
        pthread_exit(NULL);
    }

    ts_print(">> Server listening on %s:%d\n", my_address->ip, my_address->port);

    while (1)
    {
        struct sockaddr_storage clientaddr;
        socklen_t clientlen = sizeof(clientaddr);

        int connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (connfd < 0)
        {
            perror("accept");
            continue;
        }

        int *connfd_ptr = malloc(sizeof(int));
        if (!connfd_ptr)
        {
            perror("malloc");
            close(connfd);
            continue;
        }
        *connfd_ptr = connfd;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_server_request_thread, connfd_ptr);
    }

    close(listenfd);
    return NULL;
}

// ---------------------------
// main
// ---------------------------
int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = malloc(sizeof(NetworkAddress_t));
    if (!my_address)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memset(my_address, 0, sizeof(NetworkAddress_t));

    strncpy(my_address->ip, argv[1], IP_LEN - 1);
    my_address->ip[IP_LEN - 1] = '\0';
    my_address->port = atoi(argv[2]);

    if (!error_helper(my_address->ip, my_address->port))
    {
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    if (!fgets(password, sizeof(password), stdin))
    {
        fprintf(stderr, "Failed to read password.\n");
        exit(EXIT_FAILURE);
    }
    password[strcspn(password, "\n")] = '\0';

    // Use fixed salt for testing (as you had)
    char salt[SALT_LEN + 1] = "0123456789ABCDEF";
    memcpy(my_address->salt, salt, SALT_LEN);

    // IMPORTANT: use actual password length, not PASSWORD_LEN
    get_signature(password, (int)strlen(password), my_address->salt, &my_address->signature);

    network = malloc(sizeof(NetworkAddress_t *) * MAX_PEERS);
    if (!network)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    network[0] = my_address;
    peer_count = 1;

    // Debug print signature
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
        ts_print("%02x", my_address->signature[i]);
    ts_print("\n");

    srand((unsigned int)time(NULL));

    pthread_t client_thread_id;
    pthread_t server_thread_id;

    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    free_network();
    free(my_address);

    return 0;
}
