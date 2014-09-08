/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.


Changes by Pedro A. Hortas:
 - Significant changes were performed to allow smooth integration with secretbox and libpsec.

*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "crypt/chacha/ecrypt-sync.h"

#include "arch.h"
#include "tc.h"

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void _chacha_core(
	unsigned char output[64],
	const uint32_t input[16],
	size_t rounds)
{
  uint32_t x[16];
  int i = 0;

  tc_memcpy(x, input, 64);

  for (i = rounds; i > 0; i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }

  for (i = 0; i < 16; ++ i)
	x[i] = PLUS(x[i], input[i]);

  for (i = 0; i < 16; ++ i)
	arch_mem_copy_dword2vect_little(output + (i * 4), x[i]);
}

static void _crypto_core_chacha_constant(uint32_t *input, size_t kbits) {
  const char sigma[16] = "expand 32-byte k";
  const char tau[16] = "expand 16-byte k";
  const char *constants = ((kbits == 256) ? sigma : tau);

  arch_mem_copy_vect2dword_little(&input[0], (const unsigned char *) constants + 0);
  arch_mem_copy_vect2dword_little(&input[1], (const unsigned char *) constants + 4);
  arch_mem_copy_vect2dword_little(&input[2], (const unsigned char *) constants + 8);
  arch_mem_copy_vect2dword_little(&input[3], (const unsigned char *) constants + 12);
}

static void _crypto_core_chacha_key(uint32_t *input, const unsigned char *k, size_t kbits) {
  arch_mem_copy_vect2dword_little(&input[4], k + 0);
  arch_mem_copy_vect2dword_little(&input[5], k + 4);
  arch_mem_copy_vect2dword_little(&input[6], k + 8);
  arch_mem_copy_vect2dword_little(&input[7], k + 12);

  k += ((kbits == 256) ? 16 : 0);

  arch_mem_copy_vect2dword_little(&input[8], k + 0);
  arch_mem_copy_vect2dword_little(&input[9], k + 4);
  arch_mem_copy_vect2dword_little(&input[10], k + 8);
  arch_mem_copy_vect2dword_little(&input[11], k + 12);
}

static void _crypto_core_chacha_block_counter(uint32_t *input, uint32_t bc) {
  arch_mem_copy_dword2dword_little(&input[12], bc);
}

static void _crypto_core_chacha_nonce_const(uint32_t *input, uint32_t nc) {
  arch_mem_copy_dword2dword_little(&input[13], nc);
}

static void _crypto_core_chacha_nonce(uint32_t *input, const unsigned char *n) {
  arch_mem_copy_vect2dword_little(&input[14], n + 0);
  arch_mem_copy_vect2dword_little(&input[15], n + 4);
}

void crypto_core_chacha(
	unsigned char output[64],
	const unsigned char k[32],
	const unsigned char n[8],
	uint32_t nc,
	uint32_t bc,
	size_t kbits,
	size_t rounds)
{
  uint32_t input[16];

  _crypto_core_chacha_constant(input, kbits);
  _crypto_core_chacha_key(input, k, kbits);
  _crypto_core_chacha_block_counter(input, bc);
  _crypto_core_chacha_nonce_const(input, nc);
  _crypto_core_chacha_nonce(input, n);

  _chacha_core(output, input, rounds);
}

int crypto_stream_chacha_xor(
	unsigned char *c,
	const unsigned char *m,
	size_t mlen,
	const unsigned char *n,
	const unsigned char *k,
	uint32_t nc,
	uint32_t bc,
	size_t kbits,
	size_t rounds)
{
  unsigned char output[64];
  uint32_t input[16];
  int i = 0;

  /* Constant setup */
  _crypto_core_chacha_constant(input, kbits);

  /* Key setup */
  _crypto_core_chacha_key(input, k, kbits);

  /* block counter setup */
  _crypto_core_chacha_block_counter(input, bc);

  /* nonce constant setup */
  _crypto_core_chacha_nonce_const(input, nc);
 
  /* nonce setup */
  _crypto_core_chacha_nonce(input, n);

  /* Encrypt bytes */
  if (!mlen) return -1;
  for (;;) {
    _chacha_core(output,input, rounds);
    input[12] = PLUSONE(input[12]);
    if (!input[12]) {
      input[13] = PLUSONE(input[13]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (mlen <= 64) {
      for (i = 0;i < mlen;++i) c[i] = m[i] ^ output[i];
      return 0;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    mlen -= 64;
    c += 64;
    m += 64;
  }

  return -1;
}

