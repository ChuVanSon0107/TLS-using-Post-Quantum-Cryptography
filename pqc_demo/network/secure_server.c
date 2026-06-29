#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
#include "tls_key_schedule.h"

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096
#define PUBLIC_KEY_FILE "keys/server_mldsa_public.key"
#define SECRET_KEY_FILE "keys/server_mldsa_secret.key"

void cleanup_mlkem(uint8_t *shared_secret, uint8_t *kem_public_key, uint8_t *ciphertext, OQS_KEM *kem);
void cleanup_mldsa(uint8_t *sig_secret_key, uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig);

int main() {
    /* TCP Socket */
    int listenfd = -1, connfd = -1;
    int ret = EXIT_FAILURE;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int transcript_initialized = 0;

    /* ML-DSA */
    OQS_SIG *sig = NULL;
    uint8_t *sig_secret_key = NULL;
    uint8_t *sig_public_key = NULL;
    uint8_t *signature = NULL;
    size_t signature_length;

    /* ML-KEM */
    OQS_KEM *kem = NULL;
    uint8_t *kem_public_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;

    /* TLS APPLICATION KEY */
    tls_application_keys application_keys = {0};

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
    sig_public_key = OQS_MEM_malloc(sig->length_public_key);
    signature = OQS_MEM_malloc(sig->length_signature);
    if (sig_secret_key == NULL || sig_public_key == NULL || signature == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    // Load secret key
    if (load_file(SECRET_KEY_FILE, sig_secret_key, sig->length_secret_key) != 0) {
        fprintf(stderr, "[ERROR] Cannot load ML-DSA secret key\n");
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
        goto end;
    }

    printf("ML-KEM: %s\n", kem->method_name);
    printf("Public Key Size: %zu\n", kem->length_public_key);
    printf("Secret Key Size: %zu\n", kem->length_secret_key);
    printf("Ciphertext Size: %zu\n", kem->length_ciphertext);
    printf("Shared Secret: %zu\n", kem->length_shared_secret);

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


    /* Handshake parameters */
    int received_bytes;
    size_t body_len;
    tls_transcript transcript;
    uint8_t transcript_hash[TLS_TRANSCRIPT_HASH_LEN];
    size_t transcript_hash_len;
    uint8_t server_finished[TLS_FINISHED_VERIFY_DATA_LEN];
    uint8_t client_finished[TLS_FINISHED_VERIFY_DATA_LEN];
    uint8_t expected_client_finished[TLS_FINISHED_VERIFY_DATA_LEN];

    /* Init transcript */
    if (transcript_init(&transcript) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize transcript\n");
        goto end;
    }

    transcript_initialized = 1;

    /* 1. Receive Client Hello */
    received_bytes = recv_handshake_msg(connfd, TLS_MSG_CLIENT_HELLO, kem_public_key, kem->length_public_key, &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Client Hello\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    printf("[SERVER] Received Client Hello\n");

    if (body_len != kem->length_public_key) {
        fprintf(stderr, "[ERROR] Invalid Client Hello length\n");
        goto end;
    }

    /* Update transcript after receiving ClientHello */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_CLIENT_HELLO, kem_public_key, kem->length_public_key) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* 2. Send Server Hello */
    /* Encapsulation => shared_secret + ciphertext */
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, kem_public_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_KEM_encaps failed!\n");
        goto end;
    }

    printf("[OK] Encapsulation completed\n");

    /* Send ciphertext */
    if (send_handshake_msg(connfd, TLS_MSG_SERVER_HELLO, ciphertext, kem->length_ciphertext) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Hello\n");
        goto end;
    }

    printf("[SERVER] Sent Server Hello\n");

    /* Update transcript after sending ServerHello */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_SERVER_HELLO, ciphertext, kem->length_ciphertext) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* 3. Send Certificate */
    /* This Certificate message carries a raw ML-DSA public key */
    if (send_handshake_msg(connfd, TLS_MSG_CERTIFICATE, sig_public_key, sig->length_public_key) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Certificate\n");
        goto end;
    }

    printf("[SERVER] Sent Certificate\n");

    /* Update transcript after sending Certificate */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_CERTIFICATE, sig_public_key, sig->length_public_key) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* 4. Send CertificateVerify */
    /* Get hash value for transcript to sign */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get transcript hash\n");
        goto end;
    }

    /* Sign transcript hash */
    if (OQS_SIG_sign(sig, signature, &signature_length, transcript_hash, transcript_hash_len, sig_secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "[ERROR] OQS_SIG_sign failed\n");
        goto end;
    }

    printf("[OK] Signed transcript hash\n");

    if (send_handshake_msg(connfd, TLS_MSG_CERTIFICATE_VERIFY, signature, signature_length) == -1) {
        fprintf(stderr, "[ERROR] Failed to send CertificateVerify\n");
        goto end;
    }

    printf("[SERVER] Sent CertificateVerify\n");

    /* Update transcript after sending CertificateVerify */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_CERTIFICATE_VERIFY, signature, signature_length) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* 5. Send Server Finished */
    /* Get hash value for transcript to sign */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get transcript hash\n");
        goto end;
    }

    /* Compute MAC for transcript hash => verify data */
    if (compute_finished_verify_data(shared_secret, kem->length_shared_secret, TLS_SERVER_FINISHED_LABEL, transcript_hash, transcript_hash_len, server_finished, sizeof(server_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to compute Server Finished\n");
        goto end;
    }

    /* Send Server Finished */
    if (send_handshake_msg(connfd, TLS_MSG_FINISHED, server_finished, sizeof(server_finished)) == -1) {
        fprintf(stderr, "[ERROR] Failed to send Server Finished\n");
        goto end;
    }

    printf("[SERVER] Sent Server Finished\n");

    /* Update transcript after sending Server Finished */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_FINISHED, server_finished, sizeof(server_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }


    /* 6. Receive Client Finished */
    received_bytes = recv_handshake_msg(connfd, TLS_MSG_FINISHED, client_finished, sizeof(client_finished), &body_len);
    if (received_bytes == -1) {
        fprintf(stderr, "[ERROR] Failed to receive Client Finished\n");
        goto end;
    } else if (received_bytes == 1) {
        fprintf(stderr, "[SERVER] Connection closed\n");
        goto end;
    }

    printf("[SERVER] Received Client Finished\n");

    if (body_len != TLS_FINISHED_VERIFY_DATA_LEN) {
        fprintf(stderr, "[ERROR] Invalid Client Finished length\n");
        goto end;
    }

    /* Calculate expected Client Finished */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get transcript hash\n");
        goto end;
    }

    if (compute_finished_verify_data(shared_secret, kem->length_shared_secret, TLS_CLIENT_FINISHED_LABEL, transcript_hash, transcript_hash_len, expected_client_finished, sizeof(expected_client_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to compute expected Client Finished\n");
        goto end;
    }

    if (CRYPTO_memcmp(client_finished, expected_client_finished, TLS_FINISHED_VERIFY_DATA_LEN) != 0) {
        fprintf(stderr, "[CLIENT] Client Finished verification failed\n");
        goto end;
    }

    printf("[OK] Client Finished verified\n");

    /* Update transcript after receiving Server Finished */
    if (transcript_update_handshake_msg(&transcript, TLS_MSG_FINISHED, client_finished, sizeof(client_finished)) != 0) {
        fprintf(stderr, "[ERROR] Failed to update transcript\n");
        goto end;
    }

    /* TLS APPLICATION DATA */
    tls_record_state send_state;
    tls_record_state recv_state;
    uint8_t plaintext[1024];
    size_t plaintext_len;

    /* Generate session key (AES Key) using HKDF_SHA256 */
    if (transcript_get_hash(&transcript, transcript_hash, sizeof(transcript_hash), &transcript_hash_len) != 0) {
        fprintf(stderr, "[ERROR] Failed to get final transcript hash\n");
        goto end;
    }

    if (derive_application_keys(shared_secret, kem->length_shared_secret, transcript_hash, transcript_hash_len, &application_keys) != 0) {
        fprintf(stderr, "[ERROR] Failed to derive application keys\n");
        goto end;
    }

    printf("[SERVER] Generated Application Keys\n");

    /* Init TLS RECORD State */
    if (tls_record_state_init(&recv_state, application_keys.client_key, application_keys.client_iv) != 0 || tls_record_state_init(&send_state, application_keys.server_key, application_keys.server_iv) != 0) {
        fprintf(stderr, "[ERROR] Failed to initialize record states\n");
        goto end;
    }


    /* 7. Received an application data record from Client */
    if (recv_encrypted_record(connfd, plaintext, sizeof(plaintext) - 1, &plaintext_len, &recv_state) != 0) {
        fprintf(stderr, "[ERROR] Failed to receive encrypted application record\n");
        goto end;
    }  

    plaintext[plaintext_len] = '\0';

    printf("[SERVER] Received Application Data record from Client\n");
    printf("[OK] Decrypted message: %s\n", plaintext);

    /* 8. Send an application data record to Client */
    const char *message = "Hello Secure PQC from Server!";
    if (send_encrypted_record(connfd, (const uint8_t *)message, strlen(message), &send_state) != 0) {
        fprintf(stderr, "[ERROR] Failed to send encrypted application record\n");
        goto end;
    }

    printf("[SERVER] Sent Application Data record to Client\n");

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

    if (transcript_initialized) {
        transcript_free(&transcript);
    }

    OPENSSL_cleanse(&application_keys, sizeof(application_keys));

    /* Free */
    cleanup_mlkem(shared_secret, kem_public_key, ciphertext, kem);
    cleanup_mldsa(sig_secret_key, sig_public_key, signature, sig);

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

void cleanup_mldsa(uint8_t *sig_secret_key, uint8_t *sig_public_key, uint8_t *signature, OQS_SIG *sig) {
	if (sig != NULL) {
        if (sig_secret_key != NULL) {
            OQS_MEM_secure_free(sig_secret_key, sig->length_secret_key);
        }
    }

    OQS_MEM_insecure_free(sig_public_key);
    OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}
