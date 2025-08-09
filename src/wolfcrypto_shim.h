#ifndef WOLFCRYPTO_SHIM_H
#define WOLFCRYPTO_SHIM_H

#include <stdint.h>
#include <sys/types.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#if 0
#include <wolfssl/wolfcrypt/curve25519.h>

#define CURVE25519_KEY_SIZE CURVE25519_KEYSIZE

#define curve25519_generate_public curve25519_generate_public_wolfshim
void curve25519_generate_public_wolfshim(uint8_t pub[static CURVE25519_KEY_SIZE], const uint8_t secret[static CURVE25519_KEY_SIZE]);
#endif /* 0 */

#endif
