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

NetworkAddress_t** network = NULL;
uint32_t peer_count = 0;

void get_signature(void* password, int password_len, char* salt, hashdata_t* out_hash){
    int combined_len = password_len + SALT_LEN;
    char *buf = malloc(combined_len);
    if (!buf) { perror("malloc"); exit(EXIT_FAILURE); }
    memcpy(buf, password, password_len);
    memcpy(buf + password_len, salt, SALT_LEN);
    get_data_sha(buf, *out_hash, (uint32_t)combined_len, SHA256_HASH_SIZE);
    memset(buf, 0, combined_len);
    free(buf);
}

void send_message(NetworkAddress_t peer, int command, char* body, int body_len) {
    char port_str[16];
    sprintf(port_str, "%d", peer.port);

    int sock = compsys_helper_open_clientfd(peer.ip, port_str);
    if (sock < 0) {
        printf("Could not connect to %s:%d\n", peer.ip, peer.port);
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

    // Send body (not needed now, but kept for later tasks)
    if (body_len > 0) {
        compsys_helper_writen(sock, body, body_len);
    }

    // ===== Receive reply header =====
    uint8_t reply_header[REPLY_HEADER_LEN];
    compsys_helper_readn(sock, reply_header, REPLY_HEADER_LEN);

    uint32_t reply_length = ntohl(*(uint32_t*)&reply_header[0]);
    uint32_t reply_status = ntohl(*(uint32_t*)&reply_header[4]);

    if (reply_status != 1) { // STATUS_OK = 1
        printf("Register failed (status=%d)\n", reply_status);
        close(sock);
        return;
    }

    // ===== Read reply body =====
    char* reply_body = malloc(reply_length);
    compsys_helper_readn(sock, reply_body, reply_length);

    // reply_body contains peers in blocks of sizeof(NetworkAddress_t)
    int peers_in_msg = reply_length / sizeof(NetworkAddress_t);

    network = realloc(network, sizeof(NetworkAddress_t*) * (peer_count + peers_in_msg));

    for (int i = 0; i < peers_in_msg; i++) {
        NetworkAddress_t* new_peer = malloc(sizeof(NetworkAddress_t));
        memcpy(new_peer, reply_body + i * sizeof(NetworkAddress_t), sizeof(NetworkAddress_t));
        network[peer_count++] = new_peer; // <-- THIS increases peer_count
    }

    free(reply_body);
    close(sock);
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
void* client_thread()
{
    char peer_ip[IP_LEN];
    fprintf(stdout, "Enter peer IP to connect to: ");
    scanf("%16s", peer_ip);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_ip); i<IP_LEN; i++)
    {
        peer_ip[i] = '\0';
    }

    char peer_port[PORT_STR_LEN];
    fprintf(stdout, "Enter peer port to connect to: ");
    scanf("%16s", peer_port);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(peer_port); i<PORT_STR_LEN; i++)
    {
        peer_port[i] = '\0';
    }

    NetworkAddress_t peer_address;
    memset(&peer_address, 0, sizeof(peer_address));
    memcpy(peer_address.ip, peer_ip, IP_LEN);
    peer_address.port = atoi(peer_port);

    // Send REGISTER request
    send_message(peer_address, COMMAND_REGISTER, NULL, 0);

    // Print network list after registration
    printf("\nKnown peers after registration:\n");
    for (uint32_t i = 0; i < peer_count; i++) {
        printf(" - %s:%d\n", network[i]->ip, network[i]->port);
    }

return NULL;

    return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void* server_thread()
{
    // You should never see this printed in your finished implementation
    printf("Server thread done\n");

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

    my_address = (NetworkAddress_t*)malloc(sizeof(NetworkAddress_t));
    memset(my_address->ip, '\0', IP_LEN);
    memcpy(my_address->ip, argv[1], strlen(argv[1]));
    my_address->port = atoi(argv[2]);

    if (!is_valid_ip(my_address->ip)) {
        fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
        exit(EXIT_FAILURE);
    }
    
    if (!is_valid_port(my_address->port)) {
        fprintf(stderr, ">> Invalid peer port: %d\n", 
            my_address->port);
        exit(EXIT_FAILURE);
    }

    char password[PASSWORD_LEN];
    fprintf(stdout, "Create a password to proceed: ");
    scanf("%16s", password);

    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Most correctly, we should randomly generate our salts, but this can make
    // repeated testing difficult so feel free to use the hard coded salt below
    char salt[SALT_LEN+1] = "0123456789ABCDEF\0";
    //generate_random_salt(salt);
    memcpy(my_address->salt, salt, SALT_LEN);

    // Get signature 
    get_signature(password, PASSWORD_LEN, my_address->salt, &my_address->signature);
   
    // Network list allocation
    network = malloc(sizeof(NetworkAddress_t*) * 128); // starting capacity
    network[0] = my_address;
    peer_count = 1;

    // Check
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        printf("%02x", my_address->signature[i]);
    }
    printf("\n");

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