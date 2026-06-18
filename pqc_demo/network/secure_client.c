#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <openssl/crypto.h>

#include "common.h"
#include "aes_gcm.h"
#include "kdf.h"
#include "sig_utils.h"
#include "tls_handshake.h"
#include "tls_transcript.h"
#include "tls_finished.h"
#include "tls_record.h"

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
    int transcript_initialized = 0;

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_public_key = NULL;
    uint8_t *signature = NULL;
    size_t signature_length;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *kem_secret_key = NULL;
    uint8_t *shared_secret = NULL;
    uint8_t *ciphertext = NULL;
    size_t ciphertext_length;

    /* Initialize ML-DSA-65 */
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-DSA\n");
        goto end;
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

   /* Initialize ML-KEM */
    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-KEM\n");
        goto end;
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

    /* Handshake parameters */
    int received_bytes;
    size_t body_len;
    tls_transcript transcript;
    uint8_t encoded_msg[4096];
    size_t encoded_len;
    uint8_t transcript_hash[TLS_TRANSCRIPT_HASH_LEN];
    size_t transcript_hash_len;
    uint8_t server_finished[TLS_FINISHED_VERIFY_DATA_LEN];
    uint8_t expected_server_finished[TLS_FINISHED_VERIFY_DATA_LEN];
    uint8_t client_finished[TLS_FINISHED_VERIFY_DATA_LEN];

    /* Init transcript */
    if (transcript_init(&transcript) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize transcript\n");
        goto end;
    }

    transcript_initialized = 1;

    /* 1. Send Client Hello */
    if (send_handshake_msg(sockfd, TLS_MSG_CLIENT_HELLO, kem_public_key, kem->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Client Hello");
        goto end;
    }

    printf("[CLIENT] Sent Client Hello\n");

    /* Update transcript after sending ClientHello */
    if (encode_handshake_msg(TLS_MSG_CLIENT_HELLO, kem_public_key, kem->length_public_key, encoded_msg, sizeof(encoded_msg), &encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to encode ClientHello for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }


    /* 2. Receive Server Hello */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_SERVER_HELLO, ciphertext, kem->length_ciphertext, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Server Hello\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    printf("[CLIENT] Received Server Hello\n");

    ciphertext_length = body_len;
    if (ciphertext_length != kem->length_ciphertext) {
        fprintf(stderr, "[ERROR] Invalid Ciphertext length\n");
        goto end;
    } 

    /* Update transcript after receiving Server Hello */
    if (encode_handshake_msg(TLS_MSG_SERVER_HELLO, ciphertext, ciphertext_length, encoded_msg, sizeof(encoded_msg), &encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to encoded ServerHello for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }


    /* 3. Receive Certificate */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_CERTIFICATE, sig_public_key, sig->length_public_key, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Certificate\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    printf("[CLIENT] Received Certificate\n");

    if (body_len != sig->length_public_key) {
        fprintf(stderr, "[ERROR] Invalid Certificate length\n");
        goto end;
    }

    /* Update transcript after receiving Certificate */
    if (encode_handshake_msg(TLS_MSG_CERTIFICATE, sig_public_key, body_len, encoded_msg, sizeof(encoded_msg), &encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to encode Certificate for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }


    /* 4. Receive CertificateVerify */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_CERTIFICATE_VERIFY, signature, sig->length_signature, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive CertificateVerify\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    printf("[CLIENT] Received CertificateVerify\n");

    if (body_len == 0 || body_len > sig->length_signature) {
        fprintf(stderr, "[ERROR] Invalid Signature length\n");
        goto end;
    }

    signature_length = body_len;

    /* Get hash for transcript to sign */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get transcript hash\n");
        goto end;
    }

    /* Verify signature */
    if (OQS_SIG_verify(sig, transcript_hash, transcript_hash_len, signature, signature_length, sig_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[CLIENT] Signature verification failed\n");
        goto end;
    }   

    printf("[OK] Signature verified\n");

    /* Update transcript after receiving CertificateVerify */
    if (encode_handshake_msg(TLS_MSG_CERTIFICATE_VERIFY, signature, signature_length, encoded_msg, sizeof(encoded_msg), &encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to encode CertificateVerify for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }


    /* Decapsulation => shared_secret */
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, kem_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_decaps failed\n");
        goto end;
    }

    printf("[OK] Decapsulation completed\n");


    /* 5. Receive Server Finished */
    received_bytes = recv_handshake_msg(sockfd, TLS_MSG_FINISHED, server_finished, sizeof(server_finished), &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Server Finished\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[CLIENT] Connection closed\n");
        goto end;
    }

    printf("[CLIENT] Received Server Finished\n");

    if (body_len != TLS_FINISHED_VERIFY_DATA_LEN) {
        fprintf(stderr, "[ERROR] Invalid Server Finished length\n");
        goto end;
    }

    /* Calculate exptected Server Finished */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get transcript hash\n");
        goto end;
    }

    if (compute_finished_verify_data(shared_secret, kem->length_shared_secret, TLS_SERVER_FINISHED_LABEL, transcript_hash, transcript_hash_len, expected_server_finished, sizeof(expected_server_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to compute expected Server Finished\n");
        goto end;
    }

    if (CRYPTO_memcmp(server_finished, expected_server_finished, TLS_FINISHED_VERIFY_DATA_LEN) != 0) {
        fprintf(stderr, "[CLIENT] Server Finished verification failed\n");
        goto end;
    }

    printf("[OK] Server Finished verified\n");

    /* Update transcript after receiving Server Finished */
    if (encode_handshake_msg(TLS_MSG_FINISHED, server_finished, sizeof(server_finished), encoded_msg, sizeof(encoded_msg), &encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to encode Server Finished for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* 6. Send Client Finished */
    /* Get hash value for transcript => to calculate MAC */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get hash for transcript\n");
        goto end;
    }

    /* Compute MAC for transcript hash => verify data */
    if (compute_finished_verify_data(shared_secret, kem->length_shared_secret, TLS_CLIENT_FINISHED_LABEL, transcript_hash, transcript_hash_len, client_finished, sizeof(client_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to compute Client Finished\n");
        goto end;
    }

    /* Send Client Finished */
    if (send_handshake_msg(sockfd, TLS_MSG_FINISHED, client_finished, sizeof(client_finished)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Client Finished\n");
        goto end;
    }

    printf("[CLIENT] Sent Client Finished\n");

    /* Update transcript after sending Client Finished */
    if (encode_handshake_msg(TLS_MSG_FINISHED, client_finished, sizeof(client_finished), encoded_msg, sizeof(encoded_msg), &encoded_len) != 0){
        fprintf(stderr, "[ERROR] Failed to encode Client Finished for transcript\n");
        goto end;
    }

    if (transcript_update(&transcript, encoded_msg, encoded_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }



    /* Generate session key (AES Key) using HKDF_SHA256 */
    uint8_t aes_key[32];
    if (derive_aes256_key_hkdf(shared_secret, kem->length_shared_secret, aes_key, sizeof(aes_key)) != 0) {
        fprintf(stderr, "HKDF_SHA256 failed\n");
        goto end;
    }

    printf("AES Key: ");
    print_hex(aes_key, sizeof(aes_key));


    /* 7. AES Encryption and Decryption Demo */
    const char *message = "Hello Secure PQC!";
    if (send_encrypted_record(sockfd, (const uint8_t *)message, strlen(message), aes_key) != 0) {
        fprintf(stderr, "[ERROR] Failed to send encrypted application record\n");
        goto end;
    }

    printf("[CLIENT] Sent Application Data record to Server\n");

    ret = EXIT_SUCCESS;
    printf("[CLIENT] Connection closed\n");

end:
    /* Close socket */
    if (sockfd != -1) {
        close(sockfd);
    }

    if (transcript_initialized) {
        transcript_free(&transcript);
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
