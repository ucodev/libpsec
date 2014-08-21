/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes:
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "mac/poly1305/crypto.h"

int crypto_onetimeauth_poly1305_verify(
	const unsigned char *h,
	const unsigned char *in,
	unsigned long long inlen,
	const unsigned char *k)
{
  unsigned char correct[16];
  crypto_onetimeauth_poly1305(correct,in,inlen,k);
  return crypto_verify_16(h,correct);
}
