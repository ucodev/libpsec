/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes:
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "crypt/xsalsa/crypto.h"

#include <stdint.h>

typedef uint32_t uint32;

#if 0
typedef unsigned int uint32;
#endif

static const unsigned char sigma[16] = "expand 32-byte k";

int crypto_stream_salsa(
        unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k,
        unsigned int  rounds
)
{
  unsigned char in[16];
  unsigned char block[64];
  int i;
  unsigned int u;

  if (!clen) return 0;

  for (i = 0;i < 8;++i) in[i] = n[i];
  for (i = 8;i < 16;++i) in[i] = 0;

  while (clen >= 64) {
    crypto_core_salsa(c,in,k,sigma, rounds);

    u = 1;
    for (i = 8;i < 16;++i) {
      u += (unsigned int) in[i];
      in[i] = u;
      u >>= 8;
    }

    clen -= 64;
    c += 64;
  }

  if (clen) {
    crypto_core_salsa(block,in,k,sigma,rounds);
    for (i = 0;i < clen;++i) c[i] = block[i];
  }
  return 0;
}
