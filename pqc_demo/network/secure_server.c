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
#include "sig_utils.h"

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096
#define PUBLIC_KEY_FILE "keys/server_mldsa_public.key"
#define SECRET_KEY_FILE "keys/server_mldsa_secret.key"

void cleanup_mlkem(uint8_t *shared_secret, uint8_t *kem_public_key, uint8_t *ciphertext, OQS_KEM *kem);
void cleanup_mldsa(uint8_t *sig_secret_key, uint8_t *signature, OQS_SIG *sig);

int main() {
    /* TCP Socket */
    int listenfd = -1, connfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int received_bytes;
    uint32_t network_bytes; // network bytes

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_secret_key = NULL;
    uint8_t *signature = NULL;
    size_t signature_len;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;

    /* Initialize ML-DSA */
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-DSA\n");
        return EXIT_FAILURE;
    }

    printf("ML-DSA: %s\n", sig->method_name);
    printf("Public Key: %zu bytes\n", sig->length_public_key);
    printf("Secret Key: %zu bytes\n", sig->length_secret_key);
    printf("Signature : %zu bytes\n", sig->length_signature);
    
    /* Allocate memory */
    sig_secret_key = OQS_MEM_malloc(sig->length_secret_key);
    signature = OQS_MEM_malloc(sig->length_signature);
    if (sig_secret_key == NULL || signature == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    // Load secret key
    if (load_file(SECRET_KEY_FILE, sig_secret_key, sig->length_secret_key) != 0) {
        fprintf(stderr, "[ERROR] Cannot load ML-DSA secret key\n");
        goto end;
    }

   /* Initialize ML-KEM-768 */
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-KEM\n");
        return EXIT_FAILURE;
    }

    /* Allocate public key buffer */
    kem_public_key = OQS_MEM_malloc(kem->length_public_key);
    ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
    if (kem_public_key == NULL || ciphertext == NULL || shared_secret == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

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

    /* Configure socket and bind socket to port */
    memset(&server_addr, 0, sizeof(server_addr));
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

    /* 0. Accept client connection */
    connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        perror("accept");
        goto end;
    }

    printf("[SERVER] Client connected\n");

    /* 1. Receive Client Hello */
    received_bytes = recv_all(connfd, kem_public_key, kem->length_public_key);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Client Hello\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    printf("[SERVER] Received Client Hello\n");

    /* 2. Send Server Hello: Ciphertext + Signature */
    /* Encapsulation => shared_secret + ciphertext */
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, kem_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_encaps failed!\n");
        goto end;
    }

    printf("[OK] Encapsulation completed\n");

    /* Sign Ciphertext */
    if (OQS_SIG_sign(sig, signature, &signature_len, ciphertext, kem->length_ciphertext, sig_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_SIG_sign failed\n");
        goto end;
    }

    printf("[OK] Signed Ciphertext\n");

    /* Send Ciphertext length */
    network_bytes = htonl(kem->length_ciphertext);
    if (send_all(connfd, (uint8_t *)&network_bytes, sizeof(network_bytes)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Hello\n");
        goto end;
    }

    /* Send Ciphertext */
    if (send_all(connfd, ciphertext, kem->length_ciphertext) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Hello\n");
        goto end;
    }

    /* Send Signature length */
    network_bytes = htonl(signature_len);
    if (send_all(connfd, (uint8_t *)&network_bytes, sizeof(network_bytes)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Hello\n");
        goto end;
    }

    // Send Signature
    if (send_all(connfd, signature, signature_len) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Hello\n");
        goto end;
    }

    printf("[SERVER] Sent Server Hello: Kem public key and Signature\n");

    /* Generate session key (AES Key) using HKDF_SHA256 */
    uint8_t aes_key[32];
    if (derive_aes256_key_hkdf(shared_secret, kem->length_shared_secret, aes_key, sizeof(aes_key)) != 0) {
        fprintf(stderr, "HKDF_SHA256 failed\n");
        goto end;
    }

    printf("AES Key: \n");
    print_hex(aes_key, sizeof(aes_key));

    /* 3. AES Encryption and Decryption Demo */
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

    printf("[SERVER] Received Application Data from Client\n");

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
    cleanup_mlkem(shared_secret, kem_public_key, ciphertext, kem);
    cleanup_mldsa(sig_secret_key, signature, sig);

    return ret;
}

void cleanup_mlkem(uint8_t *shared_secret, uint8_t *kem_public_key, uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
        if (shared_secret != NULL) {
            OQS_MEM_secure_free(shared_secret, kem->length_shared_secret);
        }
	}
	OQS_MEM_insecure_free(kem_public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}

void cleanup_mldsa(uint8_t *sig_secret_key, uint8_t *signature, OQS_SIG *sig) {
	if (sig != NULL) {
        if (sig_secret_key != NULL) {
            OQS_MEM_secure_free(sig_secret_key, sig->length_secret_key);
        }
    }

    OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}