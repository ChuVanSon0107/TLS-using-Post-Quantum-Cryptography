#include "tls_finished.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>

/* static: only called by this file */
static int derive_finished_key(const uint8_t *shared_secret, size_t shared_secret_len, const char *label, uint8_t *finished_key, size_t finished_key_len) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;
    int ret = -1;

    if (shared_secret == NULL || label == NULL || finished_key == NULL) {
        return -1;
    }

    /* Fetch the key derivation function */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto end;
    }

    /* Create a context for key derivation operation */
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        goto end;
    }

    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    /* Set input keying material */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, shared_secret_len);
    /* Set application specific information */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)label, strlen(label));
    *p++ = OSSL_PARAM_construct_end();

    /* Dereive key */
    if  (EVP_KDF_derive(kctx, finished_key, finished_key_len, params) != 1) {
        goto end;
    }

    ret = 0;

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int compute_finished_verify_data(const uint8_t *shared_secret, size_t shared_secret_len, const char *label, const uint8_t *transcript_hash, size_t transcript_hash_len, uint8_t *verify_data, size_t verify_data_len) {
    uint8_t finished_key[TLS_FINISHED_KEY_LEN];
    unsigned int hmac_len = 0;

    if  (shared_secret == NULL || label == NULL || transcript_hash == NULL ||  verify_data == NULL) {
        return -1;
    }

    if (verify_data_len <  TLS_FINISHED_VERIFY_DATA_LEN) {
        return -1;
    }

    /* Derive key => Finished key */
    if (derive_finished_key(shared_secret, shared_secret_len, label, finished_key, sizeof(finished_key)) != 0) {
        return -1;
    }

    /* Calculate MAC using HMAC-SHA256 */
    if (HMAC(EVP_sha256(), finished_key, sizeof(finished_key), transcript_hash, transcript_hash_len, verify_data, &hmac_len) == NULL) {
        return -1;
    }

    /* Clean Finished key */
    OPENSSL_cleanse(finished_key, sizeof(finished_key));

    if (hmac_len != TLS_FINISHED_VERIFY_DATA_LEN) {
        return -1;
    }

    return 0;
}