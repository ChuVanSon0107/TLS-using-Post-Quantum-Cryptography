#include "tls_handshake.h"

#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "common.h"

int send_handshake_msg(int sockfd, uint8_t msg_type, const uint8_t *body, size_t body_len) {
    /* header = type (1 byte) + body_len (3 bytes) */
    uint8_t header[TLS_HANDSHAKE_HEADER_LEN];

    if (body_len > TLS_HANDSHAKE_MAX_BODY_LEN || (body_len > 0 && body == NULL)) {
        return -1;
    }

    header[0] = msg_type;
    header[1] = (uint8_t)((body_len >> 16) & 0xff);
    header[2] = (uint8_t)((body_len >> 8) & 0xff);
    header[3] = (uint8_t)(body_len & 0xff);

    /* Send header */
    if (send_all(sockfd, header, sizeof(header)) == -1) {
        return -1;
    }

    /* Send body */
    if (body_len > 0 && send_all(sockfd, body, body_len) == -1) {
        return -1;
    }

    return 0;
}

int recv_handshake_msg(int sockfd, uint8_t expected_type, uint8_t *body, size_t body_capacity, size_t *body_len) {
    /* header = type (1 byte) + body_len (3 bytes) */
    uint8_t header[TLS_HANDSHAKE_HEADER_LEN];
    size_t len;
    int rc;

    if (body == NULL || body_len == NULL) {
        return -1;
    }

    /* Receive header */
    rc = recv_all(sockfd, header, sizeof(header));
    if (rc != 0) {
        return rc;
    }

    len = ((size_t)header[1] << 16) | ((size_t)header[2] << 8) | (size_t)header[3];
    if (header[0] != expected_type) {
        fprintf(stderr, "[ERROR] Unexpected handshake type: got %u, expected %u\n", header[0], expected_type);
        return -1;
    }

    if (len > body_capacity) {
        fprintf(stderr, "[ERROR] Handshake message too large: %zu > %zu\n", len, body_capacity);
        return -1;
    }

    /* Receive body */
    rc = recv_all(sockfd, body, len);
    if (rc != 0) {
        return rc;
    }

    *body_len = len;
    return 0;
}

int encode_handshake_msg(uint8_t msg_type, const uint8_t *body, size_t body_len, uint8_t *out, size_t out_capacity, size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return -1;
    }

    if (body_len > TLS_HANDSHAKE_MAX_BODY_LEN || out_capacity < TLS_HANDSHAKE_HEADER_LEN + body_len) {
        return -1;
    }

    if (body_len > 0 && body == NULL) {
        return -1;
    }

    /* TLS - Handshake header: byte 0 = msg_type, byte 1-3 = body length */
    out[0] = msg_type;
    out[1] = (uint8_t)((body_len >> 16) & 0xff);
    out[2] = (uint8_t)((body_len >> 8) & 0xff);
    out[3] = (uint8_t)(body_len & 0xff);

    if (body_len > 0) {
        memcpy(out + TLS_HANDSHAKE_HEADER_LEN, body, body_len);
    }

    *out_len = TLS_HANDSHAKE_HEADER_LEN + body_len;
    return 0;
}
