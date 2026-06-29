#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "aes_gcm.h"

#define TLS_RECORD_HEADER_LEN 5
#define TLS_RECORD_VERSION 0x0303 
#define TLS_CONTENT_TYPE_APPLICATION_DATA 23
#define TLS_RECORD_MAX_PLAINTEXT_LEN 1024
#define TLS_RECORD_MAX_ENCRYPTED_LEN (AES_GCM_TAG_LEN + TLS_RECORD_MAX_PLAINTEXT_LEN)

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

typedef struct {
    uint8_t key[AES_256_KEY_LEN];
    uint8_t static_iv[AES_GCM_IV_LEN];
    uint64_t sequence_number;
} tls_record_state;

int tls_record_state_init(tls_record_state *state, const uint8_t *key, const uint8_t *static_iv);

int send_encrypted_record(int sockfd, const uint8_t *plaintext, size_t plaintext_len, tls_record_state *state);
int recv_encrypted_record(int sockfd, uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len, tls_record_state *state);

#endif