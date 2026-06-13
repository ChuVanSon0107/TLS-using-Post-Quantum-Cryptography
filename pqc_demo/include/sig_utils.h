#ifndef SIG_UTILS_H
#define SIG_UTILS_H

#include <stdint.h>
#include <oqs/oqs.h>

/*
0 if success; -1 if error
Load public key and secret key => to sign and verify
*/
int load_file(const char *filename, uint8_t *buffer, size_t expected_size);

#endif