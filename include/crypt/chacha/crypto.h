#ifndef LIBPSEC_CRYPT_CHACHA_CRYPTO_H
#define LIBPSEC_CRYPT_CHACHA_CRYPTO_H

/* Prototypes */
int crypto_core_chacha_xor(
	unsigned char *c,
	const unsigned char *m,
	size_t mlen,
	const unsigned char *n,
	const unsigned char *k,
	size_t kbits,
	size_t rounds);

#endif

