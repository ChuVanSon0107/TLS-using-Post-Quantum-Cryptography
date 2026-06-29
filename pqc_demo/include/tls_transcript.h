#ifndef TLS_TRANSCRIPT_H
#define TLS_TRANSCRIPT_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

#define TLS_TRANSCRIPT_HASH_LEN 32 // SHA-256: ouput = 32 bytes

typedef struct {
    EVP_MD_CTX *ctx; // Message Digest Context
} tls_transcript;

/* Initialize transcript hashing: 0 if success; -1 if error */
int transcript_init(tls_transcript *transcript);

/* Add an encoded handshake bytes to the transcript: 0 if success; -1 if error */
int transcript_update(tls_transcript *transcript, const uint8_t *data, size_t data_len);

/* Get the current transcript hash: 0 if success; -1 if error */
int transcript_get_hash(tls_transcript *transcript, uint8_t *hash, size_t hash_capacity, size_t *hash_len);

/* Free the OpenSSL digest context: void */
void transcript_free(tls_transcript *transcript);

/* Encode handshake message and update transcript with this encoded handshake message: 0 if success; -1 if error */
int transcript_update_handshake_msg(tls_transcript *transcript, uint8_t msg_type, const uint8_t *body, size_t body_len);

#endif