#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    const char *message = "Hello PQC";

    /* Socket creation */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    printf("[CLIENT] Socket created\n");

    memset(&server_addr, 0, sizeof(server_addr));

    /* Server address */
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return EXIT_FAILURE;
    }

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("[CLIENT] Connected to server\n");

    /* Send message */
    if (send(sockfd, message, strlen(message), 0) < 0) {
        perror("send");
        close(sockfd);
        return EXIT_FAILURE;
    }

    printf("[CLIENT] Message sent\n");

    close(sockfd);

    printf("[CLIENT] Connection closed\n");

    return EXIT_SUCCESS;
}