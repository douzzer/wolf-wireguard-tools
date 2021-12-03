#include "wolfcrypto_shim.h"
#include "encoding.h"
#include "subcommands.h"
#include "containers.h"

void curve25519_generate_public_wolfshim(uint8_t pub[static CURVE25519_KEY_SIZE], const uint8_t secret[static CURVE25519_KEY_SIZE]) {
    uint8_t secret_copy[CURVE25519_KEY_SIZE]; /* pubkey_main() calls curve25519_generate_public() with pub == secret, which doesn't work for wc_curve25519_make_pub(). */
    XMEMCPY(secret_copy, secret, CURVE25519_KEY_SIZE);
    int ret = wc_curve25519_make_pub(CURVE25519_KEY_SIZE, pub, CURVE25519_KEY_SIZE, secret_copy);
    if (ret) {
        fprintf(stderr,"curve25519 public key calculation failed: %s\n", wc_GetErrorString(ret));
        abort();
    }
    return;
}

int genkey_main(int argc, char *argv[]) {
    WC_RNG gRng;
    char base64[WG_KEY_LEN_BASE64];
    struct stat stat;

    if (argc != 1) {
        fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
        return 1;
    }

    if (!fstat(STDOUT_FILENO, &stat) && S_ISREG(stat.st_mode) && stat.st_mode & S_IRWXO)
        fputs("Warning: writing to world accessible file.\nConsider setting the umask to 077 and trying again.\n", stderr);

    {
#ifndef HAVE_FIPS
        int ret = wc_InitRng_ex(&gRng, NULL /* HEAP_HINT */, INVALID_DEVID);
#else
        int ret = wc_InitRng(&gRng);
#endif
        if (ret != 0) {
            fprintf(stderr,"InitRNG failed: %s\n", wc_GetErrorString(ret));
            return 1;
        }
    }

    if (! strcmp(argv[0],"genkey")) {
        curve25519_key key;
        int ret = wc_curve25519_init(&key);
        if (ret != 0) {
            fprintf(stderr,"wc_curve25519_init failed: %s\n", wc_GetErrorString(ret));
            return 1;
        }
        ret = wc_curve25519_make_key(&gRng, CURVE25519_KEY_SIZE, &key);
        if (ret != 0) {
            fprintf(stderr,"wc_curve25519_make_key failed: %s\n", wc_GetErrorString(ret));
            return 1;
        }
        key_to_base64(base64, key.k);
    } else {
        uint8_t key[WG_KEY_LEN];
        int ret = wc_RNG_GenerateBlock(&gRng, key, sizeof key);
        if (ret != 0) {
            fprintf(stderr,"wc_RNG_GenerateBlock failed: %s\n", wc_GetErrorString(ret));
            return 1;
        }
        key_to_base64(base64, key);
    }

    puts(base64);
    return 0;
}
