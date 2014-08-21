#ifndef LIBPSEC_CRYPT_POLY1305_CRYPTO_H
#define LIBPSEC_CRYPT_POLY1305_CRYPTO_H

#define CRYPTO_POLY1305BYTES 16

int crypto_verify_16(const unsigned char *x, const unsigned char *y);
int crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k);
int crypto_onetimeauth_poly1305_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k);

#endif

