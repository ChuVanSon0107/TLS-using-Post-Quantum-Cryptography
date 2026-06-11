#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#include "common.h"
#include "kdf.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

void cleanup_heap(uint8_t *shared_secret, uint8_t *public_key, uint8_t *ciphertext, OQS_KEM *kem);

int main() {
    /* TCP Socket */
    int sockfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;

    /* Initialize ML-KEM-768 */
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-KEM\n");
        return EXIT_FAILURE;
    }

    /* Allocate public key buffer */
    public_key = OQS_MEM_malloc(kem->length_public_key);
    ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
    if (public_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    /* Socket creation */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("socket");
        goto end;
    }

    printf("[CLIENT] Socket created\n");

    /* Server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        goto end;
    }

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        goto end;
    }

    printf("[CLIENT] Connected to server\n");

    /* Receive public key */
    if (recv_all(sockfd, public_key, kem->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to receive public key\n");
        goto end;
    }

    printf("[CLIENT] Public key received (%zu bytes)\n", kem->length_public_key);
    
    printf("First 32 bytes of public key: \n");
    print_hex(public_key, 32);

    /* Encapsulation => ciphertext and shared_secret */
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_encaps failed!\n");
        goto end;
    }

    printf("[OK] Encapsulation completed\n");

    /* Send ciphertext to client */
    if (send_all(sockfd, ciphertext, kem->length_ciphertext) == -1) {
        fprintf(stderr, "[ERROR] Failed to send ciphertext\n");
        goto end;
    }

    printf("[CLIENT] Ciphertext sent (%zu bytes)\n", kem->length_ciphertext);

    printf("[CLIENT] Shared secret: \n");
    print_hex(shared_secret, kem->length_shared_secret);

    /* Generate session key (AES Key) using HKDF_SHA256 */
    uint8_t aes_key[32];
    if (derive_aes256_key_hkdf(shared_secret, kem->length_shared_secret, aes_key, sizeof(aes_key)) != 0) {
        fprintf(stderr, "HKDF_SHA256 failed\n");
        goto end;
    }

    printf("AES Key: \n");
    print_hex(aes_key, sizeof(aes_key));

    ret = EXIT_SUCCESS;
    printf("[CLIENT] Connection closed\n");

end:
    /* Close socket */
    if (sockfd != -1) {
        close(sockfd);
    }
    
    /* Free  */
    cleanup_heap(shared_secret, public_key, ciphertext, kem);

    return ret;
}

void cleanup_heap(uint8_t *shared_secret, uint8_t *public_key, uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}