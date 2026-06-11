#include <stdio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

static unsigned char hkdf_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c
};

static unsigned char hkdf_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};


int derive_aes256_key_hkdf(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key, size_t aes_key_len) {
    EVP_KDF *kdf = NULL; // Handle đại diện cho thuật toán HKDF
    EVP_KDF_CTX *kctx = NULL; // Context thực thi cụ thể của một lần dẫn xuất khóa
    OSSL_LIB_CTX *library_context = NULL; // Môi trường thư viện riêng biệt, không ảnh hưởng global state
    OSSL_PARAM params[5], *p = params;
    int ret = -1;

    library_context = OSSL_LIB_CTX_new();
    if (library_context == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new return NULL\n");
        goto end;
    }

    /* Fetch the key derivation function */
    kdf = EVP_KDF_fetch(library_context, "HKDF", NULL);
    if (kdf == NULL) {
        fprintf(stderr, "EVP_KDF_fetch returned NULL\n");
        goto end;
    }

    /* Create a context for the key derivation operation */
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "EVP_KDF_CTX_new return NULL\n");
        goto end;
    }

    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    /* Set input keying material */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, shared_secret_len);
    /* Set application specific information */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, hkdf_info, sizeof(hkdf_info));
    /* Set salt */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, hkdf_salt, sizeof(hkdf_salt));
    *p = OSSL_PARAM_construct_end();

    /* Derive key */
    if (EVP_KDF_derive(kctx, aes_key, aes_key_len, params) != 1){
        goto end;
    }

    ret = 0;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_LIB_CTX_free(library_context);
    return ret;
}