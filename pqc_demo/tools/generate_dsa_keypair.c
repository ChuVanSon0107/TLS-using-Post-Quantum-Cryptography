#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

#define PUBLIC_KEY_FILE "../keys/server_mldsa_public.key"
#define SECRET_KEY_FILE "../keys/server_mldsa_secret.key"

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, OQS_SIG *sig);

int main() {
    OQS_STATUS rc;
	OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
    FILE *fp = NULL;
    int ret = EXIT_FAILURE;

    /* Initialize ML-DSA-65 */
    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (sig == NULL) {
        fprintf(stderr, "[ERROR] Failed to initialize ML-DSA-65");
        return EXIT_FAILURE;
    }

    printf("Algorithm: %s\n", sig->method_name);
    printf("Public Key Size: %zu bytes\n", sig->length_public_key);
    printf("Secret Key Size: %zu bytes\n", sig->length_secret_key);

    /* Allocate memory */
    public_key = OQS_MEM_malloc(sig->length_public_key);
    secret_key = OQS_MEM_malloc(sig->length_secret_key);
    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "[ERROR] Memory allocation failed\n");
        goto end;
    }

    /* Generate keypair */
    printf("\n[1] Generating ML-DSA keypair...\n");
    rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "[ERROR] OQS_SIG_keypair failed!\n");
		goto end;
    }

    printf("[OK] Keypair generated\n");

    /* Save public key */
    fp = fopen(PUBLIC_KEY_FILE, "wb");
    if (fp == NULL) {
        perror("fopen");
        goto end;
    }

    // write
    if (fwrite(public_key, 1, sig->length_public_key, fp) != sig->length_public_key) {
        fprintf(stderr, "[ERROR] Failed to write public key\n");
        fclose(fp);
        goto end;
    }

    fclose(fp);

    /* Save secret key */
    fp = fopen(SECRET_KEY_FILE, "wb");
    if (fp == NULL) {
        perror("fopen");
        goto end;
    }

    // write
    if (fwrite(secret_key, 1, sig->length_secret_key, fp) != sig->length_secret_key) {
        fprintf(stderr, "[ERROR] Failed to write secret key\n");
        fclose(fp);
        goto end;
    }

    fclose(fp);

    printf("[OK] Public key saved to %s\n", PUBLIC_KEY_FILE);
    printf("[OK] Secret key saved to %s\n", SECRET_KEY_FILE);

    // return value
    ret = EXIT_SUCCESS;

end:
    /* clean up */
    cleanup_heap(public_key, secret_key, sig);

    return ret;
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key, OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_SIG_free(sig);
}