#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "aes_gcm.h"

#define TLS_RECORD_HEADER_LEN 5
#define TLS_RECORD_VERSION 0x0303 
#define TLS_CONTENT_TYPE_APPLICATION_DATA 23
#define TLS_RECORD_MAX_PLAINTEXT_LEN 1024
#define TLS_RECORD_MAX_ENCRYPTED_LEN (AES_GCM_IV_LEN + AES_GCM_TAG_LEN + TLS_RECORD_MAX_PLAINTEXT_LEN)

int send_encrypted_record(int sockfd, const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aes_key);
int recv_encrypted_record(int sockfd, uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len, const uint8_t *aes_key);

#endif