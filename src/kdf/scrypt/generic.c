/*
 * @file generic.c
 * @brief PSEC Library
 *        scrypt Key Derivation Function interface 
 *
 * Date: 11-09-2014
 *
 * Copyright 2014 Pedro A. Hortas (pah@ucodev.org)
 *
 * DUAL LICENSED:
 * 	- Apache License Version 2.0
 *	- 2-Clause BSD License
 *
 * Apache License Version 2.0
 *
 * Copyright 2014 Pedro A. Hortas (pah@ucodev.org)
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 * 2-Clause BSD License (for parts of libscrypt):
 *
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *
 * NOTES:
 *
 * Based on scrypt documentation (by Colin Percival):
 *  - http://www.tarsnap.com/scrypt/scrypt.pdf
 *
 * libscrypt (by Colin Percival) was used as a reference implementation.
 *
 * Salsa Core is based on DJB implementation (libnacl: http://nacl.cr.yp.to/)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "arch.h"
#include "kdf.h"
#include "tc.h"

static inline uint32_t _scrypt_rotate(uint32_t u, unsigned int c) {
	return (u << c) | (u >> (32 - c));
}

static inline void _scrypt_salsa_core(unsigned char in[64], unsigned int rounds) {
	unsigned int i = 0;
	uint32_t x[16], x_orig[16];

	for (i = 0; i < 16; i ++)
		x_orig[i] = arch_mem_copy_vect2dword_little(&x[i], &in[i * 4]);

	for (i = rounds; i > 0; i -= 2) {
		x[ 4] ^= _scrypt_rotate(x[ 0] + x[12],  7);
		x[ 8] ^= _scrypt_rotate(x[ 4] + x[ 0],  9);
		x[12] ^= _scrypt_rotate(x[ 8] + x[ 4], 13);
		x[ 0] ^= _scrypt_rotate(x[12] + x[ 8], 18);
		x[ 9] ^= _scrypt_rotate(x[ 5] + x[ 1],  7);
		x[13] ^= _scrypt_rotate(x[ 9] + x[ 5],  9);
		x[ 1] ^= _scrypt_rotate(x[13] + x[ 9], 13);
		x[ 5] ^= _scrypt_rotate(x[ 1] + x[13], 18);
		x[14] ^= _scrypt_rotate(x[10] + x[ 6],  7);
		x[ 2] ^= _scrypt_rotate(x[14] + x[10],  9);
		x[ 6] ^= _scrypt_rotate(x[ 2] + x[14], 13);
		x[10] ^= _scrypt_rotate(x[ 6] + x[ 2], 18);
		x[ 3] ^= _scrypt_rotate(x[15] + x[11],  7);
		x[ 7] ^= _scrypt_rotate(x[ 3] + x[15],  9);
		x[11] ^= _scrypt_rotate(x[ 7] + x[ 3], 13);
		x[15] ^= _scrypt_rotate(x[11] + x[ 7], 18);
		x[ 1] ^= _scrypt_rotate(x[ 0] + x[ 3],  7);
		x[ 2] ^= _scrypt_rotate(x[ 1] + x[ 0],  9);
		x[ 3] ^= _scrypt_rotate(x[ 2] + x[ 1], 13);
		x[ 0] ^= _scrypt_rotate(x[ 3] + x[ 2], 18);
		x[ 6] ^= _scrypt_rotate(x[ 5] + x[ 4],  7);
		x[ 7] ^= _scrypt_rotate(x[ 6] + x[ 5],  9);
		x[ 4] ^= _scrypt_rotate(x[ 7] + x[ 6], 13);
		x[ 5] ^= _scrypt_rotate(x[ 4] + x[ 7], 18);
		x[11] ^= _scrypt_rotate(x[10] + x[ 9],  7);
		x[ 8] ^= _scrypt_rotate(x[11] + x[10],  9);
		x[ 9] ^= _scrypt_rotate(x[ 8] + x[11], 13);
		x[10] ^= _scrypt_rotate(x[ 9] + x[ 8], 18);
		x[12] ^= _scrypt_rotate(x[15] + x[14],  7);
		x[13] ^= _scrypt_rotate(x[12] + x[15],  9);
		x[14] ^= _scrypt_rotate(x[13] + x[12], 13);
		x[15] ^= _scrypt_rotate(x[14] + x[13], 18);
	}

	for (i = 0; i < 16; i ++)
		arch_mem_copy_dword2vect_little(&in[i * 4], x[i] + x_orig[i]);
}

static inline uint64_t _scrypt_integerify(uint32_t *in, uint32_t r) {
	uint32_t l = 0, h = 0;

	tc_memcpy(&l, in + (((r * 2) - 1) * 16), 4);
	tc_memcpy(&h, in + (((r * 2) - 1) * 16) + 4, 4);

	return (((uint64_t) h) << 32) | (uint64_t) l;
}

static inline void _scrypt_bmix(
	uint32_t *out,
	uint32_t *in,
	uint32_t *x,
	uint32_t r)
{
	unsigned int i = 0;
	unsigned char vect_x[64];

	tc_memcpy(vect_x, &in[((2 * r) - 1) * 16], 64);

	for (i = 0; i < (r * 2); i += 2) {
		tc_memxor(vect_x, &in[i * 16], 64);
		_scrypt_salsa_core(vect_x, 8);
		tc_memcpy(&out[i * 8], vect_x, 64);

		tc_memxor(vect_x, &in[(i * 16) + 16], 64);
		_scrypt_salsa_core(vect_x, 8);
		tc_memcpy(&out[(i * 8) + (r * 16)], vect_x, 64);
	}

	tc_memcpy(x, vect_x, 64);
}

static void _scrypt_smix(
	unsigned char *b,
	uint32_t r,
	uint64_t n,
	uint32_t *v,
	uint32_t *xyz)
{
	unsigned int i = 0;
	uint32_t *x = xyz, *y = &xyz[r * 32], *z = &xyz[r * 64];

	for (i = 0; i < (r * 32); i ++)
		arch_mem_copy_vect2dword_little(&x[i], &b[i * 4]);

	for (i = 0; i < n; i += 2) {
		tc_memcpy(&v[i * (r * 32)], x, r * 128);
		_scrypt_bmix(y, x, z, r);

		tc_memcpy(&v[(i + 1) * (r * 32)], y, r * 128);
		_scrypt_bmix(x, y, z, r);
	}

	for (i = 0; i < n; i += 2) {
		tc_memxor(x, &v[(_scrypt_integerify(x, r) & (n - 1)) * (r * 32)], r * 128);
		_scrypt_bmix(y, x, z, r);

		tc_memxor(y, &v[(_scrypt_integerify(y, r) & (n - 1)) * (r * 32)], r * 128);
		_scrypt_bmix(x, y, z, r);
	}

	for (i = 0; i < (r * 32); i ++)
		arch_mem_copy_dword2vect_little(&b[i * 4], x[i]);
}

unsigned char *scrypt_low_do(
	unsigned char *out,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	uint64_t n,
	uint32_t r,
	uint32_t p,
	size_t out_size)
{
	int errsv = 0, out_alloc = 0;
	unsigned int i = 0;
	unsigned char *b = NULL;
	uint32_t *v = NULL, *xyz = NULL;

	/* Allocate xy */
	if (!(xyz = malloc((r * 256) + 64)))
		return NULL;

	/* Allocate v */
	if (!(v = malloc((r * n) * 128)))
		return NULL;

	/* Initialize b{...} */
	if (!(b = kdf_pbkdf2_sha256(NULL, pw, pw_len, salt, salt_len, 1, (p * r) * 128))) {
		errsv = errno;
		free(xyz);
		free(v);
		errno = errsv;
		return NULL;
	}

	/* Do MF() */
	for (i = 0; i < p; i ++)
		_scrypt_smix(&b[(i * r) * 128], r, n, v, xyz);

	/* Free unused memory */
	free(xyz);
	free(v);

	/* Allocate out memory if required */
	if (!out) {
		if (!(out = malloc(out_size))) {
			errsv = errno;
			kdf_destroy(b);
			errno = errsv;
			return NULL;
		}

		out_alloc = 1;
	}

	/* Compute final output */
	if (!(kdf_pbkdf2_sha256(out, pw, pw_len, b, (p * r) * 128, 1, out_size))) {
		errsv = errno;
		kdf_destroy(b);
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	kdf_destroy(b);

	/* All good */
	return out;
}

