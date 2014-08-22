/*
chacha-ref.c version 20080118
D. J. Bernstein
Public domain.


Changes by Pedro A. Hortas:
 - Some changes were performed to allow smooth integration with libpsec.

*/

#include <stdio.h>
#include <stdint.h>

#include "crypt/chacha/ecrypt-sync.h"

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

static void chacha_wordtobyte(
	unsigned char output[64],
	const uint32_t input[16],
	size_t rounds)
{
  uint32_t x[16];
  int i = 0;

  for (i = 0;i < 16;++i) x[i] = input[i];
  for (i = rounds;i > 0;i -= 2) {
    QUARTERROUND( 0, 4, 8,12)
    QUARTERROUND( 1, 5, 9,13)
    QUARTERROUND( 2, 6,10,14)
    QUARTERROUND( 3, 7,11,15)
    QUARTERROUND( 0, 5,10,15)
    QUARTERROUND( 1, 6,11,12)
    QUARTERROUND( 2, 7, 8,13)
    QUARTERROUND( 3, 4, 9,14)
  }
  for (i = 0;i < 16;++i) x[i] = PLUS(x[i],input[i]);
  for (i = 0;i < 16;++i) U32TO8_LITTLE(output + 4 * i,x[i]);
}

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void crypto_core_chacha_key(uint32_t *input, const unsigned char *k, size_t kbits) {
  const char *constants = NULL;

  /* Key setup */
  input[4] = U8TO32_LITTLE(k + 0);
  input[5] = U8TO32_LITTLE(k + 4);
  input[6] = U8TO32_LITTLE(k + 8);
  input[7] = U8TO32_LITTLE(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  input[8] = U8TO32_LITTLE(k + 0);
  input[9] = U8TO32_LITTLE(k + 4);
  input[10] = U8TO32_LITTLE(k + 8);
  input[11] = U8TO32_LITTLE(k + 12);
  input[0] = U8TO32_LITTLE(constants + 0);
  input[1] = U8TO32_LITTLE(constants + 4);
  input[2] = U8TO32_LITTLE(constants + 8);
  input[3] = U8TO32_LITTLE(constants + 12);
}

void crypto_core_chacha_counter(uint32_t *input, uint64_t counter) {
  input[12] = (uint32_t) counter;
  input[13] = (uint32_t) (counter >> 32);
}

void crypto_core_chacha_nonce(uint32_t *input, const unsigned char *n) {
  input[14] = U8TO32_LITTLE(n + 0);
  input[15] = U8TO32_LITTLE(n + 4);
}

void crypto_core_chacha(
	unsigned char output[64],
	const unsigned char k[32],
	const unsigned char n[8],
	uint64_t counter,
	size_t kbits,
	size_t rounds)
{
  uint32_t input[16];

  crypto_core_chacha_key(input, k, kbits);
  crypto_core_chacha_counter(input, counter);
  crypto_core_chacha_nonce(input, n);

  chacha_wordtobyte(output, input, rounds);
}

int crypto_core_chacha_xor(
	unsigned char *c,
	const unsigned char *m,
	size_t mlen,
	const unsigned char *n,
	const unsigned char *k,
	uint64_t counter,
	size_t kbits,
	size_t rounds)
{
  unsigned char output[64];
  uint32_t input[16];
  int i = 0;

  /* Key setup */
  crypto_core_chacha_key(input, k, kbits);

  /* counter setup */
  crypto_core_chacha_counter(input, counter);

  /* nonce setup */
  crypto_core_chacha_nonce(input, n);

  /* Encrypt bytes */
  if (!mlen) return -1;
  for (;;) {
    chacha_wordtobyte(output,input, rounds);
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

