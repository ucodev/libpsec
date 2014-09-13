/*
version 20080912
D. J. Bernstein
Public domain.

libpsec Changes (by Pedro A. Hortas on 13/09/2014):
 - Some modifications to original file were performed in order to integrate it with libpsec.
 - Original source code from D. J. Bernstein can be found at his website: http://cr.yp.to/

*/

#include "crypt/salsa/crypto.h"

#include <stdint.h>

#include "arch.h"
#include "tc.h"

#define ROTATE(u, c) (((u) << (c)) | ((u) >> (32 - (c))))

void crypto_core_salsa_rounds(unsigned char in[64], unsigned int rounds) {
	unsigned int i = 0;
	uint32_t x[16], x_orig[16];

	for (i = 0; i < 16; i ++)
		x_orig[i] = arch_mem_copy_vect2dword_little(&x[i], &in[i * 4]);

	for (i = rounds; i > 0; i -= 2) {
		x[ 4] ^= ROTATE(x[ 0] + x[12],  7);
		x[ 8] ^= ROTATE(x[ 4] + x[ 0],  9);
		x[12] ^= ROTATE(x[ 8] + x[ 4], 13);
		x[ 0] ^= ROTATE(x[12] + x[ 8], 18);
		x[ 9] ^= ROTATE(x[ 5] + x[ 1],  7);
		x[13] ^= ROTATE(x[ 9] + x[ 5],  9);
		x[ 1] ^= ROTATE(x[13] + x[ 9], 13);
		x[ 5] ^= ROTATE(x[ 1] + x[13], 18);
		x[14] ^= ROTATE(x[10] + x[ 6],  7);
		x[ 2] ^= ROTATE(x[14] + x[10],  9);
		x[ 6] ^= ROTATE(x[ 2] + x[14], 13);
		x[10] ^= ROTATE(x[ 6] + x[ 2], 18);
		x[ 3] ^= ROTATE(x[15] + x[11],  7);
		x[ 7] ^= ROTATE(x[ 3] + x[15],  9);
		x[11] ^= ROTATE(x[ 7] + x[ 3], 13);
		x[15] ^= ROTATE(x[11] + x[ 7], 18);
		x[ 1] ^= ROTATE(x[ 0] + x[ 3],  7);
		x[ 2] ^= ROTATE(x[ 1] + x[ 0],  9);
		x[ 3] ^= ROTATE(x[ 2] + x[ 1], 13);
		x[ 0] ^= ROTATE(x[ 3] + x[ 2], 18);
		x[ 6] ^= ROTATE(x[ 5] + x[ 4],  7);
		x[ 7] ^= ROTATE(x[ 6] + x[ 5],  9);
		x[ 4] ^= ROTATE(x[ 7] + x[ 6], 13);
		x[ 5] ^= ROTATE(x[ 4] + x[ 7], 18);
		x[11] ^= ROTATE(x[10] + x[ 9],  7);
		x[ 8] ^= ROTATE(x[11] + x[10],  9);
		x[ 9] ^= ROTATE(x[ 8] + x[11], 13);
		x[10] ^= ROTATE(x[ 9] + x[ 8], 18);
		x[12] ^= ROTATE(x[15] + x[14],  7);
		x[13] ^= ROTATE(x[12] + x[15],  9);
		x[14] ^= ROTATE(x[13] + x[12], 13);
		x[15] ^= ROTATE(x[14] + x[13], 18);
	}

	for (i = 0; i < 16; i ++)
		arch_mem_copy_dword2vect_little(&in[i * 4], x[i] + x_orig[i]);
}


int crypto_core_salsa(
	unsigned char *out,
	const unsigned char *in,
	const unsigned char *k,
	const unsigned char *c,
	unsigned int rounds)
{
	tc_memcpy(out +  0, c +  0, 4);

	tc_memcpy(out +  4, k  +  0, 4);
	tc_memcpy(out +  8, k  +  4, 4);
	tc_memcpy(out + 12, k  +  8, 4);
	tc_memcpy(out + 16, k  + 12, 4);

	tc_memcpy(out + 20, c  +  4, 4);

	tc_memcpy(out + 24, in +  0, 4);
	tc_memcpy(out + 28, in +  4, 4);
	tc_memcpy(out + 32, in +  8, 4);
	tc_memcpy(out + 36, in + 12, 4);

	tc_memcpy(out + 40, c  +  8, 4);

	tc_memcpy(out + 44, k  + 16, 4);
	tc_memcpy(out + 48, k  + 20, 4);
	tc_memcpy(out + 52, k  + 24, 4);
	tc_memcpy(out + 56, k  + 28, 4);

	tc_memcpy(out + 60, c  + 12, 4);

	crypto_core_salsa_rounds(out, rounds);

	return 0;
}
