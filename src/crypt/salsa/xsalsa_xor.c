/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes:
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "crypt/salsa/crypto.h"

static const unsigned char sigma[17] = "expand 32-byte k";

int crypto_stream_xsalsa_xor(
        unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k,
        unsigned int  rounds
)
{
  unsigned char subkey[32];
  crypto_core_hsalsa(subkey,n,k,sigma,rounds);
  return crypto_stream_salsa_xor(c,m,mlen,n + 16,subkey,rounds);
}
