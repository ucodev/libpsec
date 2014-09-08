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

#include "arch.h"

typedef uint32_t uint32;

static uint32 rotate(uint32 u,int c)
{
  return (u << c) | (u >> (32 - c));
}

int crypto_core_hsalsa20(
        unsigned char *out,
  const unsigned char *in,
  const unsigned char *k,
  const unsigned char *c
)
{
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32 j0, j5, j6, j7, j8, j9, j10, j15;
  int i;

  j0 = arch_mem_copy_vect2dword_little(&x0, c + 0);

  arch_mem_copy_vect2dword_little(&x1, k + 0);
  arch_mem_copy_vect2dword_little(&x2, k + 4);
  arch_mem_copy_vect2dword_little(&x3, k + 8);
  arch_mem_copy_vect2dword_little(&x4, k + 12);

  j5 = arch_mem_copy_vect2dword_little(&x5, c + 4);

  j6 = arch_mem_copy_vect2dword_little(&x6, in + 0);
  j7 = arch_mem_copy_vect2dword_little(&x7, in + 4);
  j8 = arch_mem_copy_vect2dword_little(&x8, in + 8);
  j9 = arch_mem_copy_vect2dword_little(&x9, in + 12);

  j10 = arch_mem_copy_vect2dword_little(&x10, c + 8);

  arch_mem_copy_vect2dword_little(&x11, k + 16);
  arch_mem_copy_vect2dword_little(&x12, k + 20);
  arch_mem_copy_vect2dword_little(&x13, k + 24);
  arch_mem_copy_vect2dword_little(&x14, k + 28);

  j15 = arch_mem_copy_vect2dword_little(&x15, c + 12);

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

  x5 += j5;
  x6 += j6;
  x7 += j7;
  x8 += j8;
  x9 += j9;
  x10 += j10;

  x15 += j15;

  x0 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, c + 0);
  x5 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, c + 4);
  x10 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, c + 8);
  x15 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, c + 12);

  x6 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, in + 0);
  x7 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, in + 4);
  x8 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, in + 8);
  x9 -= arch_mem_copy_vect2dword_little((uint32_t [1]) { 0 }, in + 12);

  arch_mem_copy_dword2vect_little(out + 0, x0);
  arch_mem_copy_dword2vect_little(out + 4, x5);
  arch_mem_copy_dword2vect_little(out + 8, x10);
  arch_mem_copy_dword2vect_little(out + 12, x15);
  arch_mem_copy_dword2vect_little(out + 16, x6);
  arch_mem_copy_dword2vect_little(out + 20, x7);
  arch_mem_copy_dword2vect_little(out + 24, x8);
  arch_mem_copy_dword2vect_little(out + 28, x9);

  return 0;
}

