/*
 * @file generic.c
 * @brief PSEC Library
 *        Xsalsa20 Encryption/Decryption interface 
 *
 * Date: 20-08-2014
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
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "crypt/chacha/crypto.h"

unsigned char *chacha20_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	int errsv = 0, out_alloc = 0;

	if (!out) {
		if (!(out = malloc(in_len)))
			return NULL;

		out_alloc = 1;
	}

	if (crypto_core_chacha_xor(out, in, in_len, nonce, key, 256, 20) < 0) {
		errsv = errno;
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	*out_len = in_len;

	return out;
}

unsigned char *chacha20_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20_encrypt(out, out_len, in, in_len, nonce, key);
}

