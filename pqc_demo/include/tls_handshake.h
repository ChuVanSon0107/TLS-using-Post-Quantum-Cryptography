#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#define TLS_HANDSHAKE_HEADER_LEN 4
#define TLS_HANDSHAKE_MAX_BODY_LEN 0xFFFFFFu 

typedef enum {
    TLS_MSG_CLIENT_HELLO = 1,
    TLS_MSG_SERVER_HELLO = 2,
    TLS_MSG_CERTIFICATE = 11,
    TLS_MSG_CERTIFICATE_VERIFY = 15,
    TLS_MSG_FINISHED = 20
} tls_handshake_type;

/* 0 if successs; -1 if error */
int send_handshake_msg(int sockfd, uint8_t msg_type, const uint8_t *body, size_t body_len);

/* 0 if success; -1 if error */
int recv_handshake_msg(int sockfd, uint8_t expected_type, uint8_t *body, size_t body_capacity, size_t *body_len);

#endif
