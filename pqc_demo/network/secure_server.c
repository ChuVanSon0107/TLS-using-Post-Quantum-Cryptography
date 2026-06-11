#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#include "common.h"
#include "aes_gcm.h"
#include "kdf.h"

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *shared_secret, uint8_t *ciphertext, OQS_KEM *kem);

int main() {
    /* TCP Socket */
    int listenfd = -1, connfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];


    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *ciphertext = NULL;
    
    /* Initialize ML-KEM */
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-KEM\n");
        return EXIT_FAILURE;
    }

    printf("Algorithm: %s\n", kem->method_name);
    printf("Public Key Size: %zu\n", kem->length_public_key);
    printf("Secret Key Size: %zu\n", kem->length_secret_key);
    printf("Ciphertext Size: %zu\n", kem->length_ciphertext);
    printf("Shared Secret: %zu\n", kem->length_shared_secret);

    /* Allocate memory */
    public_key = OQS_MEM_malloc(kem->length_public_key);
    secret_key = OQS_MEM_malloc(kem->length_secret_key);
    shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
    ciphertext = OQS_MEM_malloc(kem->length_ciphertext);

    if (public_key == NULL || secret_key == NULL || shared_secret == NULL || ciphertext == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    /* Generate keypair */
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] Keypair generation failed\n");
        goto end;
    }

    printf("[OK] ML-KEM keypair generated\n");

    /* Socket creation */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket");
        goto end;
    }

    int opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        goto end;
    }

    /* memset */
    memset(&server_addr, 0, sizeof(server_addr));

    /* Configure socket and bind socket to port */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        goto end;
    }

    /* Start listening */
    if (listen(listenfd, 5) < 0) {
        perror("listen");
        goto end;
    }

    printf("[SERVER] Waiting for client...\n");

    /* Accept client connection */
    connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        perror("accept");
        goto end;
    }

    printf("[SERVER] Client connected\n");

    /* Send public key */
    if (send_all(connfd, public_key, kem->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to send public key\n");
        goto end;
    }

    printf("[SERVER] Public key sent (%zu bytes)\n", kem->length_public_key);
    printf("First 32 bytes of public key: \n");
    print_hex(public_key, 32);

    /* Receive ciphertext */
    int received_bytes = recv_all(connfd, ciphertext, kem->length_ciphertext);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive ciphertext\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    printf("[SERVER] Ciphertext received (%zu bytes)\n", kem->length_ciphertext);

    /* Decapsulation => shared_secret */
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_decaps failed\n");
        goto end;
    }

    printf("[OK] Decapsulation completed\n");

    printf("[SERVER] Shared secret: \n");
    print_hex(shared_secret, kem->length_shared_secret);

    /* Generate session key (AES Key) using HKDF_SHA256 */
    uint8_t aes_key[32];
    if (derive_aes256_key_hkdf(shared_secret, kem->length_shared_secret, aes_key, sizeof(aes_key)) != 0) {
        fprintf(stderr, "HKDF_SHA256 failed\n");
        goto end;
    }

    printf("AES Key: \n");
    print_hex(aes_key, sizeof(aes_key));

    /* AES Encryption and Decryption Demo */
    uint8_t iv[AES_GCM_IV_LEN];
    uint8_t tag[AES_GCM_TAG_LEN];
    uint32_t net_len;
    uint8_t ciptext[1024];
    uint8_t plaintext[1024];

    // receive IV
    received_bytes = recv_all(connfd, iv, sizeof(iv));
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive IV\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    // receive TAG
    received_bytes = recv_all(connfd, tag, sizeof(tag));
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive TAG\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    // receive Length
    received_bytes = recv_all(connfd, (uint8_t *)&net_len, sizeof(net_len));
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive IV\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }
    
    int ciptext_len = ntohl(net_len);

    // receive ciphertext
    received_bytes = recv_all(connfd, ciptext, ciptext_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive ciphertext\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    // decrypt ciphertext
    int plaintext_len = aes_gcm_decrypt(ciptext, ciptext_len, tag, aes_key, iv, plaintext);
    if (plaintext_len < 0) {
        fprintf(stderr, "[ERROR] Decrypt failed\n");
        goto end;
    }

    plaintext[plaintext_len] = '\0';
    printf("[OK] Decrypted message: %s\n", plaintext);


    ret = EXIT_SUCCESS;
    printf("[SERVER] Connection closed\n");

end:
    /* Close socket */
    if (connfd != -1) {
        close(connfd);
    }
    
    if (listenfd != -1) {
        close(listenfd);
    }

    /* Free */
    cleanup_heap(public_key, secret_key, shared_secret, ciphertext, kem);

    return ret;
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, uint8_t *shared_secret, uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
        if (secret_key != NULL) {
            OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        }

        if (shared_secret != NULL) {
            OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
        }
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}