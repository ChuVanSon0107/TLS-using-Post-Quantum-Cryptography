#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

int send_all(int sockfd, const uint8_t *buffer, size_t length);

int recv_all(int sockfd, uint8_t *buffer, size_t length);

void print_hex(const uint8_t *data, size_t len);

#endif