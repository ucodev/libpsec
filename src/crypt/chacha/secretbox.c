/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes:
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "crypt/chacha/crypto.h"
#include "mac/poly1305/crypto.h"

int crypto_secretbox_chacha(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k,
  size_t rounds
)
{
  int i;
  unsigned char subkey[64];
  if (mlen < 32) return -1;
  crypto_core_chacha(subkey, k, n, 0, 256, rounds);
  crypto_core_chacha_xor(c,m,mlen,n,k,0,256,rounds);
  crypto_onetimeauth_poly1305(c + 16,c + 32,mlen - 32,subkey);
  for (i = 0;i < 16;++i) c[i] = 0;
  return 0;
}

int crypto_secretbox_chacha_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k,
  size_t rounds
)
{
  int i;
  unsigned char subkey[64];
  if (clen < 32) return -1;
  crypto_core_chacha(subkey, k, n, 0, 256, rounds);
  if (crypto_onetimeauth_poly1305_verify(c + 16,c + 32,clen - 32,subkey) != 0) return -1;
  crypto_core_chacha_xor(m,c,clen,n,k,0,256,rounds);
  for (i = 0;i < 32;++i) m[i] = 0;
  return 0;
}
