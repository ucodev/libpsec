/*
 * @file generic.c
 * @brief PSEC Library
 *        Blowfish Encryption/Decryption generic interface 
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
#include <stdlib.h>

#include "tc.h"

#include "crypt/blowfish/blowfish.h"

unsigned char *blowfish448ecb_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	int i = 0;
	unsigned char block[8];
	blowfish_context context;

	if (!out) {
		if (!(out = malloc(in_len)))
			return NULL;
	}

	blowfish_low_init(&context, key, 56);

	for (i = 0; i < in_len; i += 8) {
		tc_memset(block, 0, 8);
		tc_memcpy(block, in + i, (i + 8) > in_len ? in_len - i : 8);

		blowfish_low_encrypt(&context, out + i, block);
	}

	tc_memset(&context, 0, sizeof(context));

	*out_len = in_len;

	return out;
}

unsigned char *blowfish448ecb_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	int i = 0;
	unsigned char block[8];
	blowfish_context context;

	if (!out) {
		if (!(out = malloc(in_len)))
			return NULL;
	}

	blowfish_low_init(&context, key, 56);

	for (i = 0; i < in_len; i += 8) {
		tc_memcpy(block, in + i, 8);

		blowfish_low_decrypt(&context, out + i, block);
	}

	tc_memset(&context, 0, sizeof(context));

	*out_len = in_len;

	return out;
}

