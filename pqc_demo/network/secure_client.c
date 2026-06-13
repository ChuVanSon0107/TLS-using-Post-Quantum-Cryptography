#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#include "common.h"
#include "aes_gcm.h"
#include "kdf.h"
#include "sig_utils.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define PUBLIC_KEY_FILE "keys/server_mldsa_public.key"
#define SECRET_KEY_FILE "keys/server_mldsa_secret.key"

void cleanup_mlkem(uint8_t *shared_secret, uint8_t *kem_public_key, uint8_t *ciphertext, OQS_KEM *kem);
void cleanup_mldsa(uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig);

int main() {
    /* TCP Socket */
    int sockfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr;

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_public_key = NULL;
    uint8_t *signature = NULL;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;

    /* Initialize ML-DSA-65 */
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
    sig_public_key = OQS_MEM_malloc(sig->length_public_key);
    signature = OQS_MEM_malloc(sig->length_signature);
    if (sig_public_key == NULL || signature  == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    // Load public key
    if (load_file(PUBLIC_KEY_FILE, sig_public_key, sig->length_public_key) != 0) {
        fprintf(stderr, "[ERROR] Cannot load ML-DSA public key\n");
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

    /* Receive public key and signature */
    int received_bytes, sig_len, pk_len;
    uint32_t net_len;

    
    // receive public key length
    received_bytes = recv_all(sockfd, (uint8_t *)&net_len, sizeof(net_len));
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Public key length\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    pk_len = ntohl(net_len);
    if (pk_len != kem->length_public_key) {
        fprintf(stderr, "[ERROR] Invalid Public key length\n");
        goto end;
    }

    // receive public key
    received_bytes = recv_all(sockfd, kem_public_key, kem->length_public_key);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive public key\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    // receive signature length
    received_bytes = recv_all(sockfd, (uint8_t *)&net_len, sizeof(net_len));
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Signature length\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    sig_len = ntohl(net_len);

    // receive signature
    received_bytes = recv_all(sockfd, signature, sig->length_signature);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Signature\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    printf("[CLIENT] Public key received\n");

    /* Verify signature */
    if (OQS_SIG_verify(sig, kem_public_key, pk_len, signature, sig_len, sig_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[CLIENT] Signature verification failed\n");
        goto end;
    }   

    printf("[OK] Signature verified\n");

    /* Encapsulation => ciphertext and shared_secret */
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, kem_public_key) != OQS_SUCCESS) {
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

    /* Generate session key (AES Key) using HKDF_SHA256 */
    uint8_t aes_key[32];
    if (derive_aes256_key_hkdf(shared_secret, kem->length_shared_secret, aes_key, sizeof(aes_key)) != 0) {
        fprintf(stderr, "HKDF_SHA256 failed\n");
        goto end;
    }

    printf("AES Key: \n");
    print_hex(aes_key, sizeof(aes_key));


    /* AES Encryption and Decryption Demo */
    const char *message = "Hello Secure PQC!";
    uint8_t iv[AES_GCM_IV_LEN];
    uint8_t tag[AES_GCM_TAG_LEN];
    uint8_t ciptext[1024];
    OQS_randombytes(iv, sizeof(iv));

    // Encrypt message
    int ciptext_len = aes_gcm_encrypt((const uint8_t *)message, strlen(message), aes_key, iv, ciptext, tag);
    if (ciptext_len < 0) {
        fprintf(stderr, "[ERROR] Encryption failed\n");
        goto end;
    }

    printf("[OK] Encrypted message: \n");
    printf("IV: \n");
    print_hex(iv, sizeof(iv));
    printf("TAG: \n");
    print_hex(tag, sizeof(tag));
    printf("Ciphertext: \n");
    print_hex(ciptext, ciptext_len);

    // Send IV
    if (send_all(sockfd, iv, sizeof(iv)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send IV\n");
        goto end;
    }

    // send TAG
    if (send_all(sockfd, tag, sizeof(tag)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send TAG\n");
        goto end;
    }

    // send length
    net_len = htonl(ciptext_len);
    if (send_all(sockfd, (uint8_t *)&net_len, sizeof(net_len)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send length of ciphertext\n");
        goto end;
    }

    // send ciphertext
    if (send_all(sockfd, ciptext, ciptext_len) == -1) {
        fprintf(stderr, "[ERROR] Failed to send ciphertext\n");
        goto end;  
    }

    ret = EXIT_SUCCESS;
    printf("[CLIENT] Connection closed\n");

end:
    /* Close socket */
    if (sockfd != -1) {
        close(sockfd);
    }
    
    /* Free */
    cleanup_mlkem(shared_secret, kem_public_key, ciphertext, kem);
    cleanup_mldsa(sig_public_key,  signature, sig);

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

void cleanup_mldsa(uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig) {
	if (sig != NULL) {
        if (sig_public_key != NULL) {
            OQS_MEM_secure_free(sig_public_key, sig->length_public_key);
        }
    }

    OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}