#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16
#define AES_256_KEY_LEN 32

/* Return the number of bytes of ciphertext; -1 if error */
int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag
);

/* Return the number of bytes of plaintext; -1 if error */
int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext
);

typedef enum {
    AES_SUCCESS = 0,
    AES_ERROR = -1
} AES_STATUS;

#endif