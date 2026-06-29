#include "tls_key_schedule.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#define TLS_CLIENT_KEY_LABEL "pqc tls demo client application key"
#define TLS_SERVER_KEY_LABEL "pqc tls demo server application key"
#define TLS_CLIENT_IV_LABEL "pqc tls demo client application iv"
#define TLS_SERVER_IV_LABEL "pqc tls demo server application iv"

static int hkdf_derive_label(
    const uint8_t *secret,
    size_t secret_len,
    const uint8_t *salt,
    size_t salt_len,
    const char *label,
    uint8_t *out,
    size_t out_len
) {
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    OSSL_PARAM params[5];
    OSSL_PARAM *p = params;
    int result = -1;

    if (secret == NULL || secret_len == 0 || salt == NULL || salt_len == 0 || label == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    /* Fetch the key derivation function */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        goto end;
    }

    /* Create a context for the key derivation operation */
    ctx = EVP_KDF_CTX_new(kdf);
    if (ctx == NULL) {
        goto end;
    }

    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    /* Set input keying material */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)secret, secret_len);
    /* Set application specific information */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)label, strlen(label));
    /* Set salt */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    *p = OSSL_PARAM_construct_end();

    /* Derive key */
    if (EVP_KDF_derive(ctx, out, out_len, params) != 1) {
        goto end;
    }

    result = 0;

end:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    return result;
}

int derive_application_keys(
    const uint8_t *shared_secret,
    size_t shared_secret_len,
    const uint8_t *transcript_hash,
    size_t transcript_hash_len,
    tls_application_keys *keys
) {
    if (shared_secret == NULL || shared_secret_len == 0 || transcript_hash == NULL || transcript_hash_len == 0 || keys == NULL) {
        return -1;
    } 

    memset(keys, 0, sizeof(*keys));

    /* Derive application key */
    /* Salt = transcript hash */
    if (hkdf_derive_label(shared_secret, shared_secret_len, transcript_hash, transcript_hash_len, TLS_CLIENT_KEY_LABEL, keys->client_key, sizeof(keys->client_key)) != 0 ||
        hkdf_derive_label(shared_secret, shared_secret_len, transcript_hash, transcript_hash_len, TLS_SERVER_KEY_LABEL, keys->server_key, sizeof(keys->server_key)) != 0 ||
        hkdf_derive_label(shared_secret, shared_secret_len, transcript_hash, transcript_hash_len, TLS_CLIENT_IV_LABEL, keys->client_iv, sizeof(keys->client_iv)) != 0 ||
        hkdf_derive_label(shared_secret, shared_secret_len, transcript_hash, transcript_hash_len, TLS_SERVER_IV_LABEL, keys->server_iv, sizeof(keys->server_iv)) != 0) {
        OPENSSL_cleanse(keys, sizeof(*keys));
        return -1;
    }

    return 0;
}