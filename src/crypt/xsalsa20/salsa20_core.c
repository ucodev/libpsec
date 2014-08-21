/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes:
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "crypt/xsalsa20/crypto.h"

#define ROUNDS 20

#include <stdint.h>

#define is_littleendian() (*(unsigned char *) (unsigned int [1]) { 1 })

#define load(x) \
	(is_littleendian() ? _load_littleendian((x)) : _load_bigendian((x)))

#define store(x,u) \
	do { \
		if (is_littleendian()) _store_littleendian((x),(u)); \
		else _store_bigendian((x),(u)); \
	} while (0)

typedef uint32_t uint32;

#if 0
typedef unsigned int uint32;
#endif

static uint32 rotate(uint32 u,int c)
{
  return (u << c) | (u >> (32 - c));
}

static uint32 _load_bigendian(const unsigned char *x)
{
  return
    (((uint32) (x[0])) << 24) \
  | (((uint32) (x[1])) << 16) \
  | (((uint32) (x[2])) << 8)  \
  |   (uint32) (x[3])
  ;
}

static uint32 _load_littleendian(const unsigned char *x)
{
  return
      (uint32) (x[0]) \
  | (((uint32) (x[1])) << 8) \
  | (((uint32) (x[2])) << 16) \
  | (((uint32) (x[3])) << 24)
  ;
}

static void _store_bigendian(unsigned char *x,uint32 u)
{
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

static void _store_littleendian(unsigned char *x,uint32 u)
{
  x[0] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[3] = u;
}

int crypto_core_salsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  int i;

  j0 = x0 = load(c + 0);
  j1 = x1 = load(k + 0);
  j2 = x2 = load(k + 4);
  j3 = x3 = load(k + 8);
  j4 = x4 = load(k + 12);
  j5 = x5 = load(c + 4);
  j6 = x6 = load(in + 0);
  j7 = x7 = load(in + 4);
  j8 = x8 = load(in + 8);
  j9 = x9 = load(in + 12);
  j10 = x10 = load(c + 8);
  j11 = x11 = load(k + 16);
  j12 = x12 = load(k + 20);
  j13 = x13 = load(k + 24);
  j14 = x14 = load(k + 28);
  j15 = x15 = load(c + 12);

  for (i = ROUNDS;i > 0;i -= 2) {
     x4 ^= rotate( x0+x12, 7);
     x8 ^= rotate( x4+ x0, 9);
    x12 ^= rotate( x8+ x4,13);
     x0 ^= rotate(x12+ x8,18);
     x9 ^= rotate( x5+ x1, 7);
    x13 ^= rotate( x9+ x5, 9);
     x1 ^= rotate(x13+ x9,13);
     x5 ^= rotate( x1+x13,18);
    x14 ^= rotate(x10+ x6, 7);
     x2 ^= rotate(x14+x10, 9);
     x6 ^= rotate( x2+x14,13);
    x10 ^= rotate( x6+ x2,18);
     x3 ^= rotate(x15+x11, 7);
     x7 ^= rotate( x3+x15, 9);
    x11 ^= rotate( x7+ x3,13);
    x15 ^= rotate(x11+ x7,18);
     x1 ^= rotate( x0+ x3, 7);
     x2 ^= rotate( x1+ x0, 9);
     x3 ^= rotate( x2+ x1,13);
     x0 ^= rotate( x3+ x2,18);
     x6 ^= rotate( x5+ x4, 7);
     x7 ^= rotate( x6+ x5, 9);
     x4 ^= rotate( x7+ x6,13);
     x5 ^= rotate( x4+ x7,18);
    x11 ^= rotate(x10+ x9, 7);
     x8 ^= rotate(x11+x10, 9);
     x9 ^= rotate( x8+x11,13);
    x10 ^= rotate( x9+ x8,18);
    x12 ^= rotate(x15+x14, 7);
    x13 ^= rotate(x12+x15, 9);
    x14 ^= rotate(x13+x12,13);
    x15 ^= rotate(x14+x13,18);
  }

  x0 += j0;
  x1 += j1;
  x2 += j2;
  x3 += j3;
  x4 += j4;
  x5 += j5;
  x6 += j6;
  x7 += j7;
  x8 += j8;
  x9 += j9;
  x10 += j10;
  x11 += j11;
  x12 += j12;
  x13 += j13;
  x14 += j14;
  x15 += j15;

  store(out + 0,x0);
  store(out + 4,x1);
  store(out + 8,x2);
  store(out + 12,x3);
  store(out + 16,x4);
  store(out + 20,x5);
  store(out + 24,x6);
  store(out + 28,x7);
  store(out + 32,x8);
  store(out + 36,x9);
  store(out + 40,x10);
  store(out + 44,x11);
  store(out + 48,x12);
  store(out + 52,x13);
  store(out + 56,x14);
  store(out + 60,x15);

  return 0;
}
