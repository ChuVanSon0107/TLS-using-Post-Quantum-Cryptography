#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <oqs/oqs.h>

#define MESSAGE_LEN 50

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);

int main() {
    OQS_STATUS rc;
	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	size_t message_len = MESSAGE_LEN;
	size_t signature_len;

    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: Cannot initialize ML-DSA-65\n");
        return OQS_ERROR;
    }

    printf("Algorithm: %s\n", sig->method_name);
    printf("\n=== ML-DSA Parameters ===\n");
    printf("Public Key: %zu bytes\n", sig->length_public_key);
    printf("Secret Key: %zu bytes\n", sig->length_secret_key);
    printf("Signature : %zu bytes\n", sig->length_signature);

	public_key = OQS_MEM_malloc(sig->length_public_key);
	secret_key = OQS_MEM_malloc(sig->length_secret_key);
	signature = OQS_MEM_malloc(sig->length_signature);
	message = OQS_MEM_malloc(message_len);

	if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}

	OQS_randombytes(message, message_len);

    printf("\n[1] Generating keypair...\n");

    rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_keypair failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
    }

    printf("[OK] Keypair generated\n");

    printf("\n[2] Signing message...\n");
    
    rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_sign failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
    }

    printf("[OK] Signature generated\n");

    printf("\nMessage:\n%s\n", message);

    printf("\nSignature Length: %zu bytes\n",
           signature_len);

    printf("\n[3] Verifying signature...\n");

	rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_verify failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
		return OQS_ERROR;
	}

    printf("SUCCESS: Signature Valid\n");

	cleanup_heap(public_key, secret_key, message, signature, sig);
	return OQS_SUCCESS; // success
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}