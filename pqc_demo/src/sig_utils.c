#include <stdio.h>

#include "sig_utils.h"

/* Load public key and secret key => to sign and verify*/
int load_file(const char *filename, uint8_t *buffer, size_t expected_size) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    size_t n = fread(buffer, 1, expected_size, fp);
    if (n != expected_size) {
        fprintf(stderr, "[ERROR] Invalid key file\n");
        return -1;
    }

    return 0;
}
