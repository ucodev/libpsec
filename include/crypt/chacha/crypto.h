#ifndef LIBPSEC_CRYPT_CHACHA_CRYPTO_H
#define LIBPSEC_CRYPT_CHACHA_CRYPTO_H

#define CRYPTO_NONCEBYTES 8
#define CRYPTO_ZEROBYTES 32
#define CRYPTO_BOXZEROBYTES 16

#include <stdio.h>

/* Prototypes */
int crypto_core_chacha_xor(
	unsigned char *c,
	const unsigned char *m,
	size_t mlen,
	const unsigned char *n,
	const unsigned char *k,
	size_t kbits,
	size_t rounds);
int crypto_secretbox_chacha(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k, size_t rounds);
int crypto_secretbox_chacha_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k, size_t rounds);


#endif

