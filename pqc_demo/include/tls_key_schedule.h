#ifndef TLS_KEY_SCHEDULE_H
#define TLS_KEY_SCHEDULE_H

#include <stddef.h>
#include <stdint.h>

#define TLS_APPLICATION_KEY_LEN 32
#define TLS_APPLICATION_IV_LEN 12

typedef struct {
    uint8_t client_key[TLS_APPLICATION_KEY_LEN];
    uint8_t server_key[TLS_APPLICATION_KEY_LEN];
    uint8_t client_iv[TLS_APPLICATION_IV_LEN];
    uint8_t server_iv[TLS_APPLICATION_IV_LEN];
} tls_application_keys;

int derive_application_keys(
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *transcript_hash,
    size_t transcript_hash_len,
    tls_application_keys *keys
);


#endif