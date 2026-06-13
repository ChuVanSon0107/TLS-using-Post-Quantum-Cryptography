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

void cleanup_mlkem(uint8_t *kem_public_key, uint8_t *kem_secret_key, uint8_t *shared_secret, uint8_t *ciphertext, OQS_KEM *kem);
void cleanup_mldsa(uint8_t *sig_secret_key, uint8_t *signature, OQS_SIG *sig);

int main() {
    /* TCP Socket */
    int listenfd = -1, connfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_secret_key = NULL;
    uint8_t *signature = NULL;
    size_t signature_len;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *kem_secret_key = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *ciphertext = NULL;

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

    /* Initialize ML-KEM */
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-KEM\n");
        return EXIT_FAILURE;
    }

    printf("ML-KEM: %s\n", kem->method_name);
    printf("Public Key Size: %zu\n", kem->length_public_key);
    printf("Secret Key Size: %zu\n", kem->length_secret_key);
    printf("Ciphertext Size: %zu\n", kem->length_ciphertext);
    printf("Shared Secret: %zu\n", kem->length_shared_secret);

    /* Allocate memory */
    kem_public_key = OQS_MEM_malloc(kem->length_public_key);
    kem_secret_key = OQS_MEM_malloc(kem->length_secret_key);
    shared_secret = OQS_MEM_malloc(kem->length_shared_secret);
    ciphertext = OQS_MEM_malloc(kem->length_ciphertext);

    if (kem_public_key == NULL || kem_secret_key == NULL || shared_secret == NULL || ciphertext == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    /* Generate keypair */
    if (OQS_KEM_keypair(kem, kem_public_key, kem_secret_key) != OQS_SUCCESS) {
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

    /* Sign public key before sending to client */
    if (OQS_SIG_sign(sig, signature, &signature_len, kem_public_key, kem->length_public_key, sig_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_SIG_sign failed\n");
        goto end;
    }

    printf("[OK] Signed KEM public key\n");


    /* Send public key and signature */
    // Send Public key length
    uint32_t pk_len = htonl(kem->length_public_key);
    if (send_all(connfd, (uint8_t *)&pk_len, sizeof(pk_len)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send public key length\n");
        goto end;
    }

    // Send Public key
    if (send_all(connfd, kem_public_key, kem->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to send public key\n");
        goto end;
    }

    // Send Signature length
    uint32_t sig_len_net = htonl(signature_len);
    if (send_all(connfd, (uint8_t *)&sig_len_net, sizeof(sig_len_net)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send signature length\n");
        goto end;
    }

    // Send Signature
    if (send_all(connfd, signature, signature_len) == -1) {
        fprintf(stderr, "[ERROR] Failed to send signature\n");
        goto end;
    }

    printf("[SERVER] Public key and Signature sent\n");

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
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, kem_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_decaps failed\n");
        goto end;
    }

    printf("[OK] Decapsulation completed\n");

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
    cleanup_mlkem(kem_public_key, kem_secret_key, shared_secret, ciphertext, kem);
    cleanup_mldsa(sig_secret_key, signature, sig);

    return ret;
}

void cleanup_mlkem(uint8_t *kem_public_key, uint8_t *kem_secret_key, uint8_t *shared_secret, uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
        if (kem_secret_key != NULL) {
            OQS_MEM_secure_free(kem_secret_key, kem->length_secret_key);
        }

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