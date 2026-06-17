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
#include "tls_handshake.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define PUBLIC_KEY_FILE "keys/server_mldsa_public.key"
#define SECRET_KEY_FILE "keys/server_mldsa_secret.key"

void cleanup_mlkem(uint8_t *kem_public_key, uint8_t *kem_secret_key, uint8_t *shared_secret, uint8_t *ciphertext, OQS_KEM *kem);
void cleanup_mldsa(uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig);

int main() {
    /* TCP Socket */
    int sockfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr;
    int received_bytes;
    size_t signature_length;
    size_t ciphertext_length;
    uint32_t network_bytes; // network bytes
    size_t body_len;

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_public_key = NULL;
    uint8_t *signature = NULL;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *kem_secret_key = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *ciphertext = NULL;

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

    /* 0. Connect to server */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        goto end;
    }

    printf("[CLIENT] Connected to server\n");

    /* 1. Send Client Hello */
    if (send_handshake_msg(sockfd, TLS_MSG_CLIENT_HELLO, kem_public_key, kem->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Client Hello");
        goto end;
    }

    printf("[CLIENT] Sent Client Hello\n");

    /* 2. Receive Server Hello */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_SERVER_HELLO, ciphertext, kem->length_ciphertext, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Server Hello\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    ciphertext_length = body_len;
    if (ciphertext_length != kem->length_ciphertext) {
        fprintf(stderr, "[ERROR] Invalid Ciphertext length\n");
        goto end;
    }

    /* Receive CertificateVerify */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_CERTIFICATE_VERIFY, signature, sig->length_signature, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive CertificateVerify\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    if (body_len == 0 || body_len > sig->length_signature) {
        fprintf(stderr, "[ERROR] Invalid Signature length\n");
        goto end;
    }

    signature_length = body_len;

    printf("[CLIENT] Received Server Hello\n");

    /* Verify signature */
    if (OQS_SIG_verify(sig, ciphertext, ciphertext_length, signature, signature_length, sig_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[CLIENT] Signature verification failed\n");
        goto end;
    }   

    printf("[OK] Signature verified\n");

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


    /* 3. AES Encryption and Decryption Demo */
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
    printf("IV: ");
    print_hex(iv, sizeof(iv));
    printf("TAG: ");
    print_hex(tag, sizeof(tag));
    printf("Ciphertext: ");
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
    network_bytes = htonl(ciptext_len);
    if (send_all(sockfd, (uint8_t *)&network_bytes, sizeof(network_bytes)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send length of ciphertext\n");
        goto end;
    }

    // send ciphertext
    if (send_all(sockfd, ciptext, ciptext_len) == -1) {
        fprintf(stderr, "[ERROR] Failed to send ciphertext\n");
        goto end;  
    }

    printf("[CLIENT] Sent Application Data to Server\n");

    ret = EXIT_SUCCESS;
    printf("[CLIENT] Connection closed\n");

end:
    /* Close socket */
    if (sockfd != -1) {
        close(sockfd);
    }
    
    /* Free */
    cleanup_mlkem(kem_public_key, kem_secret_key, shared_secret, ciphertext, kem);
    cleanup_mldsa(sig_public_key,  signature, sig);

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

void cleanup_mldsa(uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig) {
	if (sig != NULL) {
        if (sig_public_key != NULL) {
            OQS_MEM_secure_free(sig_public_key, sig->length_public_key);
        }
    }

    OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}
