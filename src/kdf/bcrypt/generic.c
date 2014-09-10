/*
 * @file generic.c
 * @brief PSEC Library
 *        bcrypt Key Derivation Function interface 
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypt/blowfish/blowfish.h"

#include "tc.h"

static void _bcrypt_init(blowfish_context *context) {
	/* Initialize context */
	tc_memset(context, 0, sizeof(blowfish_context));
	tc_memcpy(context->P, Pi, sizeof(Pi));
	tc_memcpy(context->S, Si, sizeof(Si));
}

static void _bcrypt_expand_key(
	blowfish_context *context,
	const unsigned char *key,
	size_t key_len,
	const unsigned char salt[16])
{
	unsigned int i = 0, j = 0, l = 0;
	unsigned char p[8], s[8];
	unsigned char ctext[8];
	uint32_t k = 0;

	for (i = 1, j = 0; i < (NROUNDS + 2); i ++) {
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

	blowfish_low_encrypt(context, ctext, salt);

	tc_memcpy(&context->P[1], ctext, 8);

	for (i = 3; i < (NROUNDS + 2); i += 2) {
		for (l = 0; l < 8; l ++)
			ctext[l] ^= salt[8 + l];

		blowfish_low_encrypt(context, p, ctext);
		tc_memcpy(&context->P[i], p, 8);
		tc_memcpy(ctext, p, 8);
	}

	for (i = 0; i < 4; i ++) {
		for (j = 0; j < 256; j += 2) {
			for (l = 0; l < 8; l ++)
				ctext[l] ^= salt[8 + l];

			blowfish_low_encrypt(context, s, ctext);
			tc_memcpy(&context->S[i][j], s, 8);
			tc_memcpy(ctext, s, 8);
		}
	}
}

static void _bcrypt_setup(
	blowfish_context *context,
	unsigned int cost,
	const unsigned char *key,
	size_t key_len,
	const unsigned char salt[16])
{
	unsigned int i = 0;
	unsigned char zero[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

	_bcrypt_init(context);

	_bcrypt_expand_key(context, key, key_len, salt); 

	for (i = 0; i < (2 << (cost - 1)); i ++) {
		_bcrypt_expand_key(context, key, key_len, zero);
		_bcrypt_expand_key(context, salt, 16, zero);
	}
}

unsigned char *bcrypt_low_do(
	unsigned char *out,
	unsigned int cost,
	const unsigned char *key,
	size_t key_len,
	const unsigned char salt[16])
{
	unsigned int i = 0;
	blowfish_context context;
	unsigned char ctext[] = "OrpheanBeholderScryDoubt";
	unsigned char c[24];

	_bcrypt_setup(&context, cost, key, key_len, salt);

	for (i = 0; i < 64; i ++) {
		blowfish_low_encrypt(&context, c, ctext);
		blowfish_low_encrypt(&context, c + 8, ctext + 8);
		blowfish_low_encrypt(&context, c + 16, ctext + 16);

		tc_memcpy(ctext, c, 24);
	}

	if (!out) {
		if (!(out = malloc(24)))
			return NULL;
	}

	tc_memcpy(out, ctext, 24);

	return out;
}

