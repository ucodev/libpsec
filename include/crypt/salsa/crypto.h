#ifndef LIBPSEC_CRYPT_SALSA_CRYPTO_H
#define LIBPSEC_CRYPT_SALSA_CRYPTO_H

#define CRYPTO_KEYBYTES 32
#define CRYPTO_NONCEBYTES 24
#define CRYPTO_ZEROBYTES 32
#define CRYPTO_BOXZEROBYTES 16

int crypto_core_salsa(unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c, unsigned int rounds);
int crypto_core_hsalsa(unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c, unsigned int rounds);
int crypto_stream_xsalsa(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k, unsigned int rounds);
int crypto_stream_salsa_xor(unsigned char *c, const unsigned char *m,unsigned long long mlen, const unsigned char *n, const unsigned char *k, unsigned int rounds);
int crypto_stream_salsa(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k, unsigned int rounds);
int crypto_stream_xsalsa_xor(unsigned char *c, const unsigned char *m,unsigned long long mlen, const unsigned char *n, const unsigned char *k, unsigned int rounds);
int crypto_secretbox_xsalsa(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k, unsigned int rounds);
int crypto_secretbox_xsalsa_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k, unsigned int rounds);

#endif

