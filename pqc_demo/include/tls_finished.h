#ifndef TLS_FINISHED_H
#define TLS_FINISHED_H

#include <stddef.h>
#include <stdint.h>

#define TLS_FINISHED_VERIFY_DATA_LEN 32
#define TLS_FINISHED_KEY_LEN 32
#define TLS_SERVER_FINISHED_LABEL "Server Finished Key"
#define TLS_CLIENT_FINISHED_LABEL "Client Finished Key"

int compute_finished_verify_data(const uint8_t *shared_secret, size_t shared_secret_len, const char *label, const uint8_t *transcript_hash, size_t transcript_hash_len, uint8_t *verify_data, size_t verify_data_len);

#endif