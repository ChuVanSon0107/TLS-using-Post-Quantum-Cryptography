#include "tls_record.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#include "common.h"

static int send_record_header(int sockfd, uint8_t content_type, uint16_t length) {
    /* record header = content_type (1 byte) + version (2 byte) + length (2 byte) */
    uint8_t header[TLS_RECORD_HEADER_LEN];

    header[0] = content_type;
    header[1] = (uint8_t)((TLS_RECORD_VERSION >> 8) & 0xff);
    header[2] = (uint8_t)(TLS_RECORD_VERSION & 0xff);
    header[3] = (uint8_t)((length >> 8) & 0xff);
    header[4] = (uint8_t)(length & 0xff);

    return send_all(sockfd, header, sizeof(header));
}

static int recv_record_header(int sockfd, uint8_t *content_type, uint16_t *length) {
    uint8_t header[TLS_RECORD_HEADER_LEN];
    int rc;

    if (content_type == NULL || length == NULL) {
        return -1;
    }

    /* Receive header */
    rc = recv_all(sockfd, header, sizeof(header));
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


/*
Demo:  
record header:
  content_type: 1 byte
  version:      2 bytes
  length:       2 bytes

encrypted_fragment:
  iv:           12 bytes
  tag:          16 bytes
  ciphertext:   variable
*/

int send_encrypted_record(int sockfd, const uint8_t *plaintext, size_t plaintext_len, const uint8_t *aes_key) {
    uint8_t iv[AES_GCM_IV_LEN];
    uint8_t tag[AES_GCM_TAG_LEN];
    uint8_t ciphertext[TLS_RECORD_MAX_PLAINTEXT_LEN];
    uint16_t encrypted_len;
    int ciphertext_len;

    if (plaintext == NULL || aes_key == NULL) {
        return -1;
    }

    if (plaintext_len == 0 || plaintext_len > TLS_RECORD_MAX_PLAINTEXT_LEN) {
        return -1;
    } 

    /* Initial Vector */
    OQS_randombytes(iv, sizeof(iv));

    /* Encrypt */
    ciphertext_len = aes_gcm_encrypt(plaintext, (int)plaintext_len, aes_key, iv, ciphertext, tag);
    if (ciphertext_len < 0) {
        return -1;
    }

    encrypted_len = (uint16_t)(AES_GCM_IV_LEN + AES_GCM_TAG_LEN + ciphertext_len);

    /* Send record header */
    if (send_record_header(sockfd, TLS_CONTENT_TYPE_APPLICATION_DATA, encrypted_len) == -1) {
        return -1;
    }

    /* Send IV */
    if (send_all(sockfd, iv, sizeof(iv)) == -1) {
        return -1;
    }

    /* Send Tag */
    if (send_all(sockfd, tag, sizeof(tag)) == -1) {
        return -1;
    }

    /* Send ciphertext */
    if (send_all(sockfd, ciphertext, (size_t)ciphertext_len) == -1) {
        return -1;
    }

    return 0;
}


int recv_encrypted_record(int sockfd, uint8_t *plaintext, size_t plaintext_capacity, size_t *plaintext_len, const uint8_t *aes_key) {
    uint8_t content_type;
    uint16_t encrypted_len;
    uint8_t iv[AES_GCM_IV_LEN];
    uint8_t tag[AES_GCM_TAG_LEN];
    uint8_t ciphertext[TLS_RECORD_MAX_PLAINTEXT_LEN];
    size_t ciphertext_len;
    int rc;
    int decrypted_len;

    if (plaintext == NULL || plaintext_len == NULL || aes_key == NULL) {
        return -1;
    }

    /* Receive record header */
    rc = recv_record_header(sockfd, &content_type, &encrypted_len);
    if (rc != 0) {
        return rc;
    }

    if (content_type != TLS_CONTENT_TYPE_APPLICATION_DATA) {
        fprintf(stderr, "[ERROR] Unexpected record content type: %u\n", content_type);
        return -1;   
    }

    if (encrypted_len <= AES_GCM_IV_LEN + AES_GCM_TAG_LEN) {
        fprintf(stderr, "[ERROR] Invalid encrypted record length\n");
        return -1; 
    }

    ciphertext_len = encrypted_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    if (ciphertext_len > sizeof(ciphertext) || ciphertext_len > plaintext_capacity) {
        fprintf(stderr, "[ERROR] Record plaintext buffer too small\n");
        return -1;
    }

    /* Receive IV */
    rc = recv_all(sockfd, iv, sizeof(iv));
    if (rc != 0) {
        return rc;
    }

    /* Receive TAG */
    rc = recv_all(sockfd, tag, sizeof(tag));
    if (rc != 0) {
        return rc;
    }

    /* Receive ciphertext */
    rc = recv_all(sockfd, ciphertext, ciphertext_len);
    if (rc != 0) {
        return rc;
    }

    decrypted_len = aes_gcm_decrypt(ciphertext, (int)ciphertext_len, tag, aes_key, iv, plaintext);
    if  (decrypted_len < 0) {
        return -1;
    }

    *plaintext_len = (size_t)decrypted_len;
    return 0;
}
