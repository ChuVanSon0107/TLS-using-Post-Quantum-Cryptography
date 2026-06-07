#include "common.h"

#include <stdio.h>
#include <sys/socket.h>

int send_all(int sockfd, const uint8_t *buffer, size_t length) {
    size_t total_sent = 0;

    while(total_sent < length) {
        ssize_t bytes_sent = send(sockfd, buffer + total_sent, length - total_sent, 0);

        if (bytes_sent <= 0) {
            return -1;
        }

        total_sent += bytes_sent;
    }

    return 0;
}

int recv_all(int sockfd, uint8_t *buffer, size_t length) {
    size_t total_received = 0;

    while(total_received < length) {
        ssize_t bytes_received = recv(sockfd, buffer + total_received, length - total_received, 0);

        if (bytes_received <= 0) {
            return -1;
        }

        total_received += bytes_received;
    }

    return 0;
}

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }

    printf("\n");
}