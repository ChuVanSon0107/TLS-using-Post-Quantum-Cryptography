#include "tls_record.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "common.h"

/* AAD = TLS RECORD HEADER */
static void encode_record_header(uint8_t header[TLS_RECORD_HEADER_LEN], uint8_t content_type, uint16_t length) {
    header[0] = content_type;
    header[1] = (uint8_t)((TLS_RECORD_VERSION >> 8) & 0xff);
    header[2] = (uint8_t)(TLS_RECORD_VERSION & 0xff);
    header[3] = (uint8_t)((length >> 8) & 0xff);
    header[4] = (uint8_t)(length & 0xff);
}

/* Make record nonce = iv (initial vector) for record */
static void make_record_nonce(const uint8_t static_iv[AES_GCM_IV_LEN], uint64_t sequence_number, uint8_t nonce[AES_GCM_IV_LEN]) {
    memcpy(nonce, static_iv, AES_GCM_IV_LEN);

    /* Nonce = static_iv XOR sequence_number */
    for (size_t i = 0; i < sizeof(sequence_number); i++) {
        nonce[AES_GCM_IV_LEN - 1 - i] ^= (uint8_t)(sequence_number >> (8 * i));
    }
}

static int recv_record_header(int sockfd, uint8_t header[TLS_RECORD_HEADER_LEN], uint8_t *content_type, uint16_t *length) {
    int rc;

    if (header == NULL || content_type == NULL || length == NULL) {
        return -1;
    }

    /* Receive header */
    rc = recv_all(sockfd, header, TLS_RECORD_HEADER_LEN);
    if (rc != 0) {
        return rc;
    }

    *content_type = header[0];
    *length = ((uint16_t)header[3] << 8) | (uint16_t)header[4];

    if (header[1] != 0x03 || header[2] != 0x03) {
        fprintf(stderr, "[ERROR] Invalid record version\n");
        return -1;
    }

    return 0;
}

int tls_record_state_init(tls_record_state *state, const uint8_t *key, const uint8_t *static_iv) {
    if (state == NULL || key == NULL || static_iv == NULL) {
        return -1;
    }

    memcpy(state->key, key, AES_256_KEY_LEN);
    memcpy(state->static_iv, static_iv, AES_GCM_IV_LEN);
    state->sequence_number = 0;
    return 0;
}

/*
Demo:  
record header:
  content_type: 1 byte
  version:      2 bytes
  length:       2 bytes

encrypted_fragment:
  ciphertext:   variable
  tag:          16 bytes
*/

int send_encrypted_record(int sockfd, const uint8_t *plaintext, size_t plaintext_len, tls_record_state *state) {
    uint8_t header[TLS_RECORD_HEADER_LEN];
    uint8_t nonce[AES_GCM_IV_LEN];
    uint8_t tag[AES_GCM_TAG_LEN];
    uint8_t ciphertext[TLS_RECORD_MAX_PLAINTEXT_LEN];
    uint16_t encrypted_len;
    int ciphertext_len;

    if (plaintext == NULL || state == NULL) {
        return -1;
    }

    if (plaintext_len == 0 || plaintext_len > TLS_RECORD_MAX_PLAINTEXT_LEN) {
        return -1;
    } 

    encrypted_len = (uint16_t)(plaintext_len + AES_GCM_TAG_LEN);

    /* tls record header */
    encode_record_header(header, TLS_CONTENT_TYPE_APPLICATION_DATA, encrypted_len);

    /* Make record nonce = inital vector (iv) */
    make_record_nonce(state->static_iv, state->sequence_number, nonce);

    /* Encrypt */
    /* AAD = TLS RECORD HEADER */
    ciphertext_len = aes_gcm_encrypt(plaintext, (int)plaintext_len, header, TLS_RECORD_HEADER_LEN, state->key, nonce, ciphertext, tag);
    if (ciphertext_len < 0) {
        return -1;
    }

    /* Send record header */
    if (send_all(sockfd, header, TLS_RECORD_HEADER_LEN) == -1) {
        return -1;
    }

    /* Send ciphertext */
    if (send_all(sockfd, ciphertext, (size_t)ciphertext_len) == -1) {
        return -1;
    }

    /* Send Tag */
    if (send_all(sockfd, tag, sizeof(tag)) == -1) {
        return -1;
    }

    /* Increment sequence number */
    state->sequence_number++;

    return 0;
}


int recv_encrypted_record(int sockfd, uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len, tls_record_state *state) {
    uint8_t content_type;
    uint16_t encrypted_len;
    uint8_t tag[AES_GCM_TAG_LEN];
    uint8_t ciphertext[TLS_RECORD_MAX_PLAINTEXT_LEN];
    size_t ciphertext_len;
    int rc;
    int decrypted_len;
    uint8_t header[TLS_RECORD_HEADER_LEN];
    uint8_t nonce[AES_GCM_IV_LEN];

    if (plaintext == NULL || plaintext_len == NULL || state == NULL) {
        return -1;
    }

    /* Receive record header */
    rc = recv_record_header(sockfd, header, &content_type, &encrypted_len);
    if (rc != 0) {
        return rc;
    }

    if (content_type != TLS_CONTENT_TYPE_APPLICATION_DATA) {
        fprintf(stderr, "[ERROR] Unexpected record content type: %u\n", content_type);
        return -1;   
    }

    if (encrypted_len <= AES_GCM_TAG_LEN) {
        fprintf(stderr, "[ERROR] Invalid encrypted record length\n");
        return -1; 
    }

    ciphertext_len = encrypted_len - AES_GCM_TAG_LEN;
    if (ciphertext_len > sizeof(ciphertext) || ciphertext_len > plaintext_capacity) {
        fprintf(stderr, "[ERROR] Record plaintext buffer too small\n");
        return -1;
    }

    /* Receive ciphertext */
    rc = recv_all(sockfd, ciphertext, ciphertext_len);
    if (rc != 0) {
        return rc;
    }

    /* Receive TAG */
    rc = recv_all(sockfd, tag, sizeof(tag));
    if (rc != 0) {
        return rc;
    }

    /* Make record nonce = iv */
    make_record_nonce(state->static_iv, state->sequence_number, nonce);

    decrypted_len = aes_gcm_decrypt(ciphertext, (int)ciphertext_len, header, TLS_RECORD_HEADER_LEN, tag, state->key, nonce, plaintext);
    if  (decrypted_len < 0) {
        return -1;
    }

    *plaintext_len = (size_t)decrypted_len;

    /* Increment sequence number */
    state->sequence_number++;

    return 0;
}
