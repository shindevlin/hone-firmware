#ifndef TWEETNACL_H
#define TWEETNACL_H

/*
 * TweetNaCl — public domain crypto library
 * Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen,
 * Tanja Lange, Peter Schwabe, Sjaak Smetsers
 * https://tweetnacl.cr.yp.to/
 *
 * Selected subset: ed25519 sign/verify (crypto_sign_*), X25519 (crypto_scalarmult*)
 *
 * Callers must provide:
 *   void randombytes(uint8_t *x, uint64_t xlen);
 * See crypto/ed25519.c for the Flipper furi_hal_random implementation.
 */

#include <stdint.h>

#define crypto_sign_BYTES        64U
#define crypto_sign_PUBLICKEYBYTES 32U
#define crypto_sign_SECRETKEYBYTES 64U

extern int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
extern int crypto_sign(uint8_t *sm, uint64_t *smlen,
                       const uint8_t *m, uint64_t mlen,
                       const uint8_t *sk);
extern int crypto_sign_open(uint8_t *m, uint64_t *mlen,
                            const uint8_t *sm, uint64_t smlen,
                            const uint8_t *pk);

/* X25519: q = n * p (n clamped), q = n * 9 */
extern int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p);
extern int crypto_scalarmult_base(uint8_t *q, const uint8_t *n);
/* SHA-512 */
extern int crypto_hash_sha512(uint8_t *out, const uint8_t *m, uint64_t n);

#endif /* TWEETNACL_H */
