#include <stdio.h>
#include <openssl/evp.h>

#include "aes_gcm.h"

/* Returns ciphertext length (> 0) if success; -1 if error */
int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *aad,
    int aad_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    /* Validate input parameters */
    if (plaintext == NULL || plaintext_len < 0 || aad_len < 0 || (aad_len > 0 && aad == NULL) || key == NULL || iv == NULL || ciphertext == NULL || tag == NULL) {
        return AES_ERROR;
    }

    /* Create and initialize OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return AES_ERROR;
    }

    /* Initialize AES-256-GCM cipher with no key or IV is supplied at this stage */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Configure IV length for GCM mode */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Set AES key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Add ADD => to calculate authentication tag */
    if (aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_ERROR;
        }
    }

    /* Encrypt plaintext. */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    ciphertext_len = len;

    /* Encryption */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    ciphertext_len += len;

    /* Retrieve authentication tag. */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* Returns plaintext length (> 0) if success; -1 if error */
int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *aad,
    int aad_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret;

    /* Validate input parameters */
    if (ciphertext == NULL || ciphertext_len < 0 || aad_len < 0 || (aad_len > 0 && aad == NULL) || key == NULL || iv == NULL || plaintext == NULL || tag == NULL) {
        return AES_ERROR;
    }

    /* Create and initialize OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return AES_ERROR;
    }

    /* Initialize AES-256-GCM cipher with no key or IV is supplied at this stage. */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Configure IV length for GCM mode */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Set AES key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Add ADD => to calculate authentication tag */
    if (aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return AES_ERROR;
        }
    }

    /* Decrypt ciphertext */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    plaintext_len = len;

    /* Set expected authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Verify tag and finalize */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        return AES_ERROR;
    }

    plaintext_len += len;

    return plaintext_len;
}