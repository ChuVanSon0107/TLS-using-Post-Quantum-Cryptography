#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096

int main() {
    int listenfd, connfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    /* Socket creation */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    printf("[SERVER] Socket created\n");

    /* memset */
    memset(&server_addr, 0, sizeof(server_addr));

    /* Configure socket and bind socket to port */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    if (bind(listenfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(listenfd);
        return EXIT_FAILURE;
    }

    printf("[SERVER] Bound to port %d\n", SERVER_PORT);

    /* Start listening */
    if (listen(listenfd, 5) < 0) {
        perror("listen");
        close(listenfd);
        return EXIT_FAILURE;
    }

    printf("[SERVER] Waiting for connection...\n");

    /* Accept client connection */
    connfd = accept(listenfd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        perror("accept");
        close(listenfd);
        return EXIT_FAILURE;
    }

    printf("[SERVER] Client connected\n");

    /* Receive data */
    int n = recv(connfd, buffer, sizeof(buffer) - 1, 0);
    if (n < 0) {
        perror("recv");
        close(connfd);
        close(listenfd);
        return EXIT_FAILURE;
    }
    buffer[n] = '\0';

    printf("\n[SERVER] Received:\n%s\n", buffer);

    close(connfd);
    close(listenfd);

    printf("\n[SERVER] Connection closed\n");
    return EXIT_SUCCESS;
}