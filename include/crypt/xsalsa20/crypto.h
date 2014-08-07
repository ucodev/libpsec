#ifndef LIBPSEC_CRYPT_CRYPTO_H
#define LIBPSEC_CRYPT_CRYPTO_H

#define CRYPTO_KEYBYTES 32
#define CRYPTO_NONCEBYTES 24
#define CRYPTO_ZEROBYTES 32
#define CRYPTO_BOXZEROBYTES 16
#define CRYPTO_POLY1305BYTES 16

int crypto_verify_16(const unsigned char *x, const unsigned char *y);
int crypto_onetimeauth_poly1305(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *k);
int crypto_onetimeauth_poly1305_verify(const unsigned char *h, const unsigned char *in, unsigned long long inlen, const unsigned char *k);
int crypto_core_salsa20(unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c);
int crypto_core_hsalsa20(unsigned char *out, const unsigned char *in, const unsigned char *k, const unsigned char *c);
int crypto_stream_xsalsa20(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
int crypto_stream_salsa20_xor(unsigned char *c, const unsigned char *m,unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_stream_salsa20(unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
int crypto_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);

#endif

