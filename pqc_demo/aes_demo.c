#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32
#define IV_LEN 12
#define TAG_LEN 16

typedef enum {
    AES_SUCCESS = 0,
    AES_ERROR = -1
} AES_STATUS;

int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag
);

int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext
);

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char key[AES_KEY_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];

    unsigned char plaintext[] = "Hello PQC AES-GCM";

    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];

    int ciphertext_len;
    int decrypted_len;

    /* Generate AES Key */
    if (RAND_bytes(key, AES_KEY_LEN) != 1) {
        fprintf(stderr, "ERROR: RAND_bytes(key) failed\n");
        return EXIT_FAILURE;
    }

    /* Generate IV */
    if (RAND_bytes(iv, IV_LEN) != 1) {
        fprintf(stderr, "ERROR: RAND_bytes(iv) failed\n");
        return EXIT_FAILURE;
    }

    /* Encrypt */
    ciphertext_len = aes_gcm_encrypt(plaintext, (int)strlen((char *)plaintext), key, iv, ciphertext, tag);

    if (ciphertext_len < 0) {
        fprintf(stderr, "ERROR: AES-GCM encryption failed\n");
        return EXIT_FAILURE;
    }

    /* Decrypt */
    decrypted_len = aes_gcm_decrypt(ciphertext, ciphertext_len, tag, key, iv, decrypted);

    if (decrypted_len < 0) {
        fprintf(stderr, "ERROR: AES-GCM authentication failed\n");
        return EXIT_FAILURE;
    }

    decrypted[decrypted_len] = '\0';

    printf("=====================================\n");
    printf("AES-256-GCM DEMO\n");
    printf("=====================================\n");

    printf("\nPlaintext:\n%s\n", plaintext);

    printf("\nAES Key (%d bytes):\n", AES_KEY_LEN);
    print_hex(key, AES_KEY_LEN);

    printf("\nIV (%d bytes):\n", IV_LEN);
    print_hex(iv, IV_LEN);

    printf("\nCiphertext (%d bytes):\n", ciphertext_len);
    print_hex(ciphertext, ciphertext_len);

    printf("\nTag (%d bytes):\n", TAG_LEN);
    print_hex(tag, TAG_LEN);

    printf("\nDecrypted:\n%s\n", decrypted);
    printf("\nSUCCESS: Encryption and Decryption completed\n");

    return EXIT_SUCCESS;
}

int aes_gcm_encrypt(
    const unsigned char *plaintext,
    int plaintext_len,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    /* Validate input parameters */
    if (!plaintext || !key || !iv || !ciphertext || !tag) {
        return AES_ERROR;
    }

    /* Create and initialize OpenSSL cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return AES_ERROR;
    }

    /*
     * Initialize AES-256-GCM cipher.
     * No key or IV is supplied at this stage.
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Configure IV length for GCM mode */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /* Set AES key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    /*
     * Encrypt plaintext.
     * The encrypted result is stored in ciphertext.
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    ciphertext_len = len;

    /*
     * Finalize encryption.
     * For GCM mode, this usually produces no extra bytes,
     * but should always be called.
     */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    ciphertext_len += len;

    /*
     * Retrieve authentication tag.
     * The receiver will use this tag to verify integrity.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_gcm_decrypt(
    const unsigned char *ciphertext,
    int ciphertext_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret;

    if (!ciphertext || !tag || !key || !iv || !plaintext) {
        return AES_ERROR;
    }

    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return AES_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return AES_ERROR;
    }

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        return AES_ERROR;
    }

    plaintext_len += len;

    return plaintext_len;
}