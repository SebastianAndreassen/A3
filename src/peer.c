#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

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

pthread_mutex_t network_mutex=PTHREAD_MUTEX_INITIALIZER; 

NetworkAddress_t* get_random_peer(const NetworkAddress_t* self) {
    pthread_mutex_lock(&network_mutex);

    if (peer_count <= 1) { // only ourselves
        pthread_mutex_unlock(&network_mutex);
        return NULL;
    }

    // Step 1: build a temporary array of eligible peers
    NetworkAddress_t* eligible[peer_count-1]; // max possible size
    uint32_t eligible_count = 0;

    for (uint32_t i = 0; i < peer_count; i++) {
        NetworkAddress_t* p = network[i];
        if (strcmp(p->ip, self->ip) != 0 || p->port != self->port) {
            eligible[eligible_count++] = p;
        }
    }

    // if (eligible_count == 0) {
    //     pthread_mutex_unlock(&network_mutex);
    //     return NULL;
    // }

    // Step 2: pick one randomly
    uint32_t index = rand() % eligible_count;
    NetworkAddress_t* chosen = eligible[index];

    pthread_mutex_unlock(&network_mutex);
    return chosen;
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


int send_message(NetworkAddress_t *peer, int command, void *body, size_t body_len)
{
    // Convert peer port to string
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", peer->port);

    // Open connection
    int sock = compsys_helper_open_clientfd(peer->ip, port_str);
    if (sock < 0) {
        fprintf(stderr, "Could not connect to %s:%d\n", peer->ip, peer->port);
        return -1;
    }


    // Build request header
    RequestHeader_t req;
    memset(&req, 0, sizeof(req));
    // Copy my_address IP safely
    strncpy(req.ip, my_address->ip, IP_LEN - 1);
    req.ip[IP_LEN - 1] = '\0';

    req.port = htonl(my_address->port);
    memcpy(req.signature, my_address->signature, SHA256_HASH_SIZE);
    req.command = htonl(command);
    req.length = htonl(body_len);

    // Send header
    if (compsys_helper_writen(sock, &req, sizeof(req)) != sizeof(req)) {
        perror("send header");
        
        return -1;
    }

    // Send body if present
    if (body_len > 0 && body != NULL) {
        if (compsys_helper_writen(sock, body, body_len) !=(ssize_t) body_len) {
            perror("send body");
            
            return -1;
        }
    }

    // Handle REGISTER reply
    if (command == COMMAND_REGISTER) {
        uint8_t reply_header[REPLY_HEADER_LEN];
        if (compsys_helper_readn(sock, reply_header, REPLY_HEADER_LEN) != REPLY_HEADER_LEN) {
            fprintf(stderr, "Failed to read REGISTER reply header\n");
            close(sock);
            return -1;
        }

        uint32_t reply_length = ntohl(*(uint32_t *)&reply_header[0]);
        uint32_t reply_status = ntohl(*(uint32_t *)&reply_header[4]);

        if (reply_status != STATUS_OK) {
            fprintf(stderr, "Register failed (status=%u)\n", reply_status);
            close(sock);
            return -1;
        }

        // Read peer list
        char *reply_body = malloc(reply_length);
        if (!reply_body) { perror("malloc"); close(sock); return -1; }
        if (compsys_helper_readn(sock, reply_body, reply_length) != reply_length) {
            fprintf(stderr, "Failed to read REGISTER reply body\n");
            free(reply_body);
            close(sock);
            return -1;
        }

        int peers_in_msg = reply_length / sizeof(NetworkAddress_t);
        for (int i = 0; i < peers_in_msg; i++) {
            NetworkAddress_t *candidate = (NetworkAddress_t *)(reply_body + i * sizeof(NetworkAddress_t));
            add_to_network_if_missing(candidate);
        }
        free(reply_body);
    }

    // Handle GET_FILE reply
    if (command == COMMAND_GET_FILE) {
    // Open the local file for writing
    char local_name[FILENAME_MAX];
    strncpy(local_name, (char *)body, body_len);
    local_name[body_len] = '\0';
    FILE *fp = fopen(local_name, "wb");
    if (!fp) { perror("fopen"); close(sock); return -1; }

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, sock);

    uint32_t total_bytes = 0;
    while (1) {
        // Read the reply header for this block
        ReplyHeader_t reply;
        if (compsys_helper_readnb(&rio, &reply, sizeof(reply)) != sizeof(reply)) {
            fprintf(stderr, "Failed to read GET_FILE reply header\n");
            fclose(fp);
            close(sock);
            return -1;
        }

        uint32_t block_len = ntohl(reply.length);
        uint32_t status = ntohl(reply.status);
        uint32_t block_num = ntohl(reply.this_block);

        if (status == STATUS_DONE) {
            printf("File transfer complete. Total bytes received: %u\n", total_bytes);
            fclose(fp);
            close(sock);
            return 0;
        }

        if (status != STATUS_OK) {
            fprintf(stderr, "File transfer failed (status=%u)\n", status);
            fclose(fp);
            close(sock);
            return -1;
        }

        // Read the block data
        char buffer[FILE_BLOCK_SIZE];
        if (block_len > FILE_BLOCK_SIZE) {
            fprintf(stderr, "Block length exceeds buffer size!\n");
            fclose(fp);
            close(sock);
            return -1;
        }

        if (compsys_helper_readnb(&rio, buffer, block_len) != (ssize_t)block_len) {
            fprintf(stderr, "Failed to read block data for block %u\n", block_num);
            fclose(fp);
            close(sock);
            return -1;
        }

        // Write the block to file
        fwrite(buffer, 1, block_len, fp);
        total_bytes += block_len;
    }

    fclose(fp);
    close(sock);

    printf("Downloaded '%s' successfully.\n", local_name);
    }
    return 0;
}


void inform_all_other_peers(NetworkAddress_t *new_peer)
{
    pthread_mutex_lock(&network_mutex);
    for (uint32_t i = 0; i < peer_count; i++)
    {
        NetworkAddress_t *p = network[i];

        if (p == my_address)
            continue;
        if (strcmp(p->ip, new_peer->ip) == 0 && p->port == new_peer->port)
            continue;

        send_message(p, COMMAND_INFORM, new_peer, sizeof(NetworkAddress_t));
    }
    pthread_mutex_unlock(&network_mutex);
}

void *handle_server_request_thread(void *arg)
{
    pthread_detach(pthread_self());
    int connfd = *((int *)arg);
    free(arg);

    compsys_helper_state_t rio;
    compsys_helper_readinitb(&rio, connfd);

    // ===== 1. Read the RequestHeader_t =====
    RequestHeader_t req;
    if (compsys_helper_readnb(&rio, &req, sizeof(RequestHeader_t)) <= 0) {
        fprintf(stderr, ">> [Server] Failed to read request header\n");
        close(connfd);
        return NULL;
    }
    uint32_t command = ntohl(req.command);
    uint32_t body_len = ntohl(req.length);
    uint32_t port = ntohl(req.port);

    printf(">> [Server] Received command=%u length=%u from %s:%u\n",
           command, body_len, req.ip, port);

    

    if (command == COMMAND_INFORM)
    {
        NetworkAddress_t new_peer;
        compsys_helper_readn(connfd, &new_peer, sizeof(NetworkAddress_t));
        add_to_network_if_missing(&new_peer);
        close(connfd);
        return NULL;
    }

    // ===== 2. Handle REGISTER command =====
    if (command == COMMAND_REGISTER)
    {

        // --- Validation ---
        if (!is_valid_ip(req.ip) || !is_valid_port(port))
        {
            printf(">> [Server] Invalid IP/port in register request.\n");
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
    if (command == COMMAND_GET_FILE) {
    if (body_len == 0 || body_len >= FILENAME_MAX) {
        fprintf(stderr, ">> [Server] Invalid filename length %u\n", body_len);
        close(connfd);
        return NULL;
    }

    char filename[FILENAME_MAX];
    memset(filename, 0, sizeof(filename));
    compsys_helper_readnb(&rio, filename, body_len);

    filename[body_len] = '\0';
    filename[strcspn(filename, "\r\n")] = '\0';

    printf(">> [Server] Client requested file: '%s'\n", filename);

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf(">> [Server] File not found: '%s'\n", filename);
        ReplyHeader_t reply = {
            .length = htonl(0),
            .status = htonl(STATUS_FILE_NOT_FOUND),
            .this_block = htonl(0)
        };
        compsys_helper_writen(connfd, &reply, sizeof(reply));
        close(connfd);
        return NULL;
    }

    char buffer[FILE_BLOCK_SIZE];
    uint32_t block_number = 0;
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, FILE_BLOCK_SIZE, fp)) > 0) {
        ReplyHeader_t reply = {
            .length = htonl((uint32_t)bytes_read),
            .status = htonl(STATUS_OK),
            .this_block = htonl(block_number)
        };
        compsys_helper_writen(connfd, &reply, sizeof(reply));
        compsys_helper_writen(connfd, buffer, bytes_read);
        block_number++;
    }

    // Send final block header to signal completion
    ReplyHeader_t end = {
        .length = htonl(0),
        .status = htonl(STATUS_DONE),
        .this_block = htonl(block_number)
    };
    compsys_helper_writen(connfd, &end, sizeof(end));

    fclose(fp);
    printf(">> [Server] Sent file '%s' in %u blocks\n", filename, block_number);
    close(connfd);
    return NULL;
}


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
    
    while (1){
        char peer_ip[IP_LEN];
        fprintf(stdout, "Enter peer IP to connect to: ");
        fgets(peer_ip, sizeof(peer_ip), stdin);
        peer_ip[strcspn(peer_ip, "\n")] = '\0';
        if(!is_valid_ip(peer_ip)){
            printf("Invalid ip,try again\n");
            continue;
        }

        char peer_port[PORT_STR_LEN];
        fprintf(stdout, "Enter peer port to connect to: ");
        fgets(peer_port, sizeof(peer_port), stdin);
        peer_port[strcspn(peer_port, "\n")] = '\0';
        if(!is_valid_port(atoi(peer_port))){
            printf("Invalid port, try again\n");
            continue;
        }
        

        NetworkAddress_t peer_address;
        memset(&peer_address, 0, sizeof(peer_address));
        memcpy(peer_address.ip, peer_ip, IP_LEN);
        peer_address.port = atoi(peer_port);

        if(send_message(&peer_address, COMMAND_REGISTER, NULL, 0)==-1){
            printf("connection failed\n");
            continue;
        }

        printf("\nKnown peers after registration:\n");
        for (uint32_t i = 0; i < peer_count; i++)
            printf(" - %s:%d\n", network[i]->ip, network[i]->port);

        char filename[FILENAME_MAX];

    
        printf("Please enter a file name: ");
        fflush(stdout);
        if (!fgets(filename, sizeof(filename), stdin)) {
            fprintf(stderr, "Error reading input.\n");
            continue;
        }
        filename[strcspn(filename, "\r\n")] = '\0';  // trim newline

        if (strlen(filename) == 0)
            continue;

        printf("Requesting file: '%s'\n", filename);

        size_t filename_len = strlen(filename);
        if (filename_len == 0)
            continue;

        // **Use a random peer for GET_FILE**, as per the guide
        NetworkAddress_t *target = get_random_peer(my_address);
        if (target == NULL) {
            fprintf(stderr, ">> [Client] No available peers to request file from\n");
            continue;
        }

        // Send the GET_FILE request with the filename in the body
        send_message(target, COMMAND_GET_FILE, filename, filename_len);
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

    printf(">> Server listening on %s:%d\n", my_address->ip, my_address->port);

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

    if (!is_valid_ip(my_address->ip))
    {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }

    if (!is_valid_port(my_address->port))
    {
        fprintf(stderr, ">> Invalid peer port: %d\n",
                my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

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
        printf("%02x", my_address->signature[i]);
    }
    printf("\n");
    
    srand((unsigned int)time(NULL));  // Seed random number generator

    // Setup the client and server threads
    pthread_t client_thread_id;
    pthread_t server_thread_id;

    pthread_create(&client_thread_id, NULL, client_thread, NULL);
    pthread_create(&server_thread_id, NULL, server_thread, NULL);

    // Wait for them to complete.
    pthread_join(client_thread_id, NULL);
    pthread_join(server_thread_id, NULL);

    exit(EXIT_SUCCESS);
}