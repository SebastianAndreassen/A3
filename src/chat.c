#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./peer.h"

// Global variables to be used by both the server and client side of the peer.
// Note the addition of mutexs to prevent race conditions.
NetworkAddress_t *my_address;

NetworkAddress_t **network = NULL;
uint32_t peer_count = 0;

pthread_mutex_t network_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;


void ts_print(const char *fmt, ...) {
    pthread_mutex_lock(&print_mutex);

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fflush(stdout);  // ensure ordered output

    pthread_mutex_unlock(&print_mutex);
}


void free_network()
{
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++)
    {
        free(network[i]);
    }
    free(network);
    pthread_mutex_unlock(&network_mutex);
}

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

// Adds candidate to network only if it's not already present.
// Returns 1 if added, 0 if it already existed.
int add_to_network_if_missing(const NetworkAddress_t *candidate)
{
    pthread_mutex_lock(&network_mutex);

    // Check for duplicates
    for (uint32_t i = 0; i < peer_count; i++)
    {
        if (strcmp(network[i]->ip, candidate->ip) == 0 &&
            network[i]->port == candidate->port)
        {
            pthread_mutex_unlock(&network_mutex);
            return 0; // already present
        }
    }

    // Add entry
    NetworkAddress_t *new_peer = malloc(sizeof(NetworkAddress_t));
    memcpy(new_peer, candidate, sizeof(NetworkAddress_t));
    network[peer_count++] = new_peer;
    pthread_mutex_unlock(&network_mutex);

    return 1;
}

void send_message(NetworkAddress_t *peer, int command, void *body, int body_len)
{
    char port_str[16];
    sprintf(port_str, "%d", peer->port);

    int sock = compsys_helper_open_clientfd(peer->ip, port_str);
    if (sock < 0)
    {
        ts_print("Could not connect to %s:%d\n", peer->ip, peer->port);
        return;
    }

    // Build request header
    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.ip, my_address->ip, IP_LEN);
    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(command);
    req.length = htonl(body_len);

    // Send header
    compsys_helper_writen(sock, &req, sizeof(RequestHeader_t));

    // Send body if present
    if (body_len > 0)
    {
        compsys_helper_writen(sock, body, body_len);
    }

    // Only wait for reply if this is REGISTER
    if (command == COMMAND_REGISTER)
    {
        // ===== Receive reply header =====
        uint8_t reply_header[REPLY_HEADER_LEN];
        compsys_helper_readn(sock, reply_header, REPLY_HEADER_LEN);

        uint32_t reply_length = ntohl(*(uint32_t *)&reply_header[0]);
        uint32_t reply_status = ntohl(*(uint32_t *)&reply_header[4]);

        if (reply_status != STATUS_OK)
        {
            ts_print("Register failed (status=%d)\n", reply_status);
            close(sock);
            return;
        }

        // ===== Read reply body =====
        char *reply_body = malloc(reply_length);
        compsys_helper_readn(sock, reply_body, reply_length);

        // reply_body contains peers in blocks of sizeof(NetworkAddress_t)
        int peers_in_msg = reply_length / sizeof(NetworkAddress_t);
        for (int i = 0; i < peers_in_msg; i++)
        {
            NetworkAddress_t *candidate = (NetworkAddress_t *)(reply_body + i * sizeof(NetworkAddress_t));
            add_to_network_if_missing(candidate);
        }

        free(reply_body);
    }

    // Close socket in all cases
    close(sock);
}

void inform_all_other_peers(NetworkAddress_t *new_peer)
{
    NetworkAddress_t *local_copy[128];
    uint32_t local_count = 0;

    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++) {
        NetworkAddress_t *p = network[i];
        if (p != my_address &&
            !(strcmp(p->ip, new_peer->ip) == 0 && p->port == new_peer->port))
        {
            local_copy[local_count++] = p;
        }
    }
    pthread_mutex_unlock(&network_mutex);

    for (uint32_t i = 0; i < local_count; i++) {
        send_message(local_copy[i], COMMAND_INFORM, new_peer, sizeof(NetworkAddress_t));
    }
}


void *handle_server_request_thread(void *arg)
{
    pthread_detach(pthread_self());
    int connfd = *((int *)arg);
    free(arg);

    // ===== 1. Read the RequestHeader_t =====
    RequestHeader_t req;
    int bytes_read = compsys_helper_readn(connfd, &req, sizeof(RequestHeader_t));
    if (bytes_read != sizeof(RequestHeader_t))
    {
        fprintf(stderr, ">> [Server] Failed to read request header (got %d bytes)\n", bytes_read);
        close(connfd);
        return NULL;
    }

    // Convert network byte order
    uint32_t command = ntohl(req.command);
    uint32_t body_len = ntohl(req.length);
    uint32_t port = ntohl(req.port);

    ts_print(">> [Server] Received command=%u length=%u from %s:%u\n",
           command, body_len, req.ip, port);

    if (command == COMMAND_INFORM)
    {
        NetworkAddress_t new_peer;
        compsys_helper_readn(connfd, &new_peer, sizeof(NetworkAddress_t));

        add_to_network_if_missing(&new_peer);

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

    // ===== 2. Handle REGISTER command =====
    if (command == COMMAND_REGISTER)
    {

        // --- Validation ---
        if (!error_helper(req.ip, port))
        {
            ts_print(">> [Server] Invalid IP/port in register request.\n");
            ReplyHeader_t reply = {
                .length = htonl(0),
                .status = htonl(STATUS_MALFORMED),
                .this_block = htonl(0)};

            compsys_helper_writen(connfd, &reply, sizeof(reply));
            close(connfd);
            return NULL;
        }

        // --- Check if already exists ---
        NetworkAddress_t candidate;
        memcpy(candidate.ip, req.ip, IP_LEN);
        candidate.port = port;

        if (add_to_network_if_missing(&candidate))
        {
            // Only compute salt/signature when truly added
            NetworkAddress_t *added = network[peer_count - 1];
            generate_random_salt(added->salt);
            get_signature(req.signature, SHA256_HASH_SIZE, added->salt, &added->signature);

            inform_all_other_peers(added);
        }

        // ===== 3. Build reply body (all known peers) =====
        uint32_t body_size = peer_count * sizeof(NetworkAddress_t);
        char *reply_body = malloc(body_size);
        for (uint32_t i = 0; i < peer_count; i++)
        {
            memcpy(reply_body + i * sizeof(NetworkAddress_t),
                   network[i], sizeof(NetworkAddress_t));
        }

        // ===== 4. Send reply header + body =====
        ReplyHeader_t reply = {
            .length = htonl(body_size),
            .status = htonl(STATUS_OK),
            .this_block = htonl(0)};

        compsys_helper_writen(connfd, &reply, sizeof(ReplyHeader_t));
        compsys_helper_writen(connfd, reply_body, body_size);

        free(reply_body);
    }

    close(connfd);
    return NULL;
}

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

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */
void *client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_ip); i < IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(peer_port); i < PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memset(&peer_address, 0, sizeof(peer_address));
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // Send REGISTER request
    send_message(&peer_address, COMMAND_REGISTER, NULL, 0);
    // Print network list after registration
    ts_print("\nKnown peers after registration:\n");
    for (uint32_t i = 0; i < peer_count; i++)
    {
        ts_print(" - %s:%d\n", network[i]->ip, network[i]->port);
    }

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void *server_thread()
{
    // Convert the port number from int to string for the helper
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

        // We malloc a copy because the thread will free it
        int *connfd_ptr = malloc(sizeof(int));
        *connfd_ptr = connfd;

        pthread_t tid;
        pthread_create(&tid, NULL, handle_server_request_thread, connfd_ptr);
        // no join here — threads run detached later
    }

    close(listenfd);
    return NULL;
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what
    // config to use
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    my_address = (NetworkAddress_t *)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!error_helper(my_address->ip, my_address->port))
    {
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i = strlen(password); i < PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char salt[SALT_LEN + 1] = "0123456789ABCDEF\0";
    // generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);

    // Get signature
    get_signature(password, PASSWORD_LEN, my_address->salt, &my_address->signature);

    // Network list allocation
    network = malloc(sizeof(NetworkAddress_t *) * 128); // starting capacity
    network[0] = my_address;
    peer_count = 1;

    // Check
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
    {
        ts_print("%02x", my_address->signature[i]);
    }
    ts_print("\n");

    // Setup the client and server threads
    pthread_t client_thread_id;
    pthread_t server_thread_id;
    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    free_network();

    exit(EXIT_SUCCESS);
}