#include "tls_transcript.h"

#include <string.h>

int transcript_init(tls_transcript *transcript) {
    if (transcript == NULL) {
        return -1;
    }

    /* Clear structure */
    memset(transcript, 0, sizeof(*transcript));

    /* Init context */
    transcript->ctx = EVP_MD_CTX_new();
    if (transcript->ctx == NULL) {
        return -1;
    }

    /* Init SHA-256 */
    if (EVP_DigestInit_ex(transcript->ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(transcript->ctx);
        transcript->ctx = NULL;
        return -1;
    }    

    return 0;
}

int transcript_update(tls_transcript *transcript, const uint8_t *data, size_t data_len) {
    if (transcript == NULL || transcript->ctx == NULL) {
        return -1;
    }

    if (data_len <= 0) {
        return -1;
    }

    if (data_len > 0 && data == NULL) {
        return -1;
    }

    /* Update transcript */
    if (EVP_DigestUpdate(transcript->ctx, data, data_len) != 1) {
        return -1;
    }

    return 0;
}

int transcript_get_hash(tls_transcript *transcript, uint8_t *hash, size_t hash_capacity, size_t *hash_len) {
    EVP_MD_CTX *copy = NULL;
    unsigned int len = 0;

    if (transcript == NULL || transcript->ctx == NULL || hash == NULL || hash_len == NULL) {
        return -1;
    }

    if (hash_capacity < TLS_TRANSCRIPT_HASH_LEN) {
        return -1;
    }

    /* Copy context of transcript => when get the hash digest, finalize the copy */
    copy = EVP_MD_CTX_new();
    if (copy == NULL) {
        return -1;
    }

    if (EVP_MD_CTX_copy_ex(copy, transcript->ctx) != 1) {
        EVP_MD_CTX_free(copy);
        return -1;
    }

    /* Get the hash digest */
    if (EVP_DigestFinal_ex(copy, hash, &len) != 1) {
        EVP_MD_CTX_free(copy);
        return -1;
    }

    EVP_MD_CTX_free(copy);
    
    *hash_len = len;
    return 0;
}

void transcript_free(tls_transcript *transcript) {
    if (transcript == NULL) {
        return;
    }

    EVP_MD_CTX_free(transcript->ctx);
    transcript->ctx = NULL;
}