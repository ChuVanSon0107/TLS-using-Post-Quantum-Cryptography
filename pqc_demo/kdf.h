#ifndef KDF_H
#define KDF_H

#include <stdint.h>
#include <stddef.h>

int derive_aes256_key_hkdf(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key, size_t aes_key_len);

#endif