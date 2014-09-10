/*
 * @file blowfish.c
 * @brief PSEC Library
 *        Blowfish Encryption/Decryption low level interface 
 *
 * Date: 10-09-2014
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
 */

#include <stdint.h>

#include "arch.h"
#include "tc.h"

#include "crypt/blowfish/blowfish.h"

void blowfish_low_encrypt(
	blowfish_context *context,
	unsigned char *out,
	const unsigned char *in)
{
	unsigned int i = 0;
	uint32_t xl = 0;
	uint32_t xr = 0;

	arch_mem_copy_vect2dword_little(&xl, in);
	arch_mem_copy_vect2dword_little(&xr, in + 4);

	for (i = 0; i < NROUNDS; i += 2) {
		xl ^= context->P[i];
		xr ^= _f(xl, context->S);
		xr ^= context->P[i + 1];
		xl ^= _f(xr, context->S);
	}

	xl ^= context->P[16];
	xr ^= context->P[17];

	arch_mem_copy_dword2vect_little(out, xr);
	arch_mem_copy_dword2vect_little(out + 4, xl);
}

void blowfish_low_decrypt(
	blowfish_context *context,
	unsigned char *out,
	const unsigned char *in)
{
	unsigned int i = 0;
	uint32_t xl = 0;
	uint32_t xr = 0;

	arch_mem_copy_vect2dword_little(&xl, in);
	arch_mem_copy_vect2dword_little(&xr, in + 4);

	for (i = NROUNDS; i; i -= 2) {
		xl ^= context->P[i + 1];
		xr ^= _f(xl, context->S);
		xr ^= context->P[i];
		xl ^= _f(xr, context->S);
	}

	xr ^= context->P[0];
	xl ^= context->P[1];

	arch_mem_copy_dword2vect_little(out, xr);
	arch_mem_copy_dword2vect_little(out + 4, xl);
}

void blowfish_low_init(
	blowfish_context *context,
	const unsigned char *key,
	size_t key_len)
{
	unsigned int i = 0, j = 0;
	unsigned char p[8], p0[8], s[8];
	uint32_t k = 0;

	/* Initialize context */
	tc_memset(context, 0, sizeof(blowfish_context));
	tc_memcpy(context->P, Pi, sizeof(Pi));
	tc_memcpy(context->S, Si, sizeof(Si));

	for (i = 0, j = 0; i < (NROUNDS + 2); i ++) {
		if (j >= key_len) j = 0;
		k = key[j ++];

		if (j >= key_len) j = 0;
		k = (k << 8) | key[j ++];

		if (j >= key_len) j = 0;
		k = (k << 8) | key[j ++];

		if (j >= key_len) j = 0;
		k = (k << 8) | key[j ++];

		context->P[i] ^= k;
	}

	tc_memset(p, 0, 8);

	for (i = 0; i < (NROUNDS + 2); i += 2) {
		blowfish_low_encrypt(context, p0, p);
		tc_memcpy(&context->P[i], p0, 8);
		tc_memcpy(p, p0, 8);
	}

	for (i = 0; i < 4; i ++) {
		for (j = 0; j < 256; j += 2) {
			blowfish_low_encrypt(context, s, p);
			tc_memcpy(&context->S[i][j], s, 8);
			tc_memcpy(p, s, 8);
		}
	}
}

