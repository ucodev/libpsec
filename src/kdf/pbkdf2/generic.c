/*
 * @file generic.c
 * @brief PSEC Library
 *        Password-Based Key Derivation Function 2 interface 
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "arch.h"
#include "hash.h"
#include "mac.h"
#include "tc.h"

static unsigned char *_f_hash(
	unsigned char *out,
	unsigned char *(*hmac) (
		unsigned char *out,
		const unsigned char *key,
		size_t key_len,
		const unsigned char *msg,
		size_t msg_len
	),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	unsigned int iterations,
	uint32_t iteration)
{
	int i = 0, j = 0;
	unsigned char u[hash_len + salt_len + 4];
	unsigned char out_tmp[HASH_DIGEST_SIZE_MAX];

	if (!out) {
		if (!(out = malloc(hash_len)))
			return NULL;
	}

	tc_memcpy(u, salt, salt_len);

	arch_mem_copy_dword2vect_big(&u[salt_len], iteration);

	hmac(out_tmp, pw, pw_len, u, salt_len + 4);

	tc_memcpy(u, out_tmp, hash_len);
	tc_memcpy(out, u, hash_len);

	for (i = 1; i < iterations; i ++) {
		hmac(out_tmp, pw, pw_len, u, hash_len);

		tc_memcpy(u, out_tmp, hash_len);

		for (j = 0; j < hash_len; j ++)
			out[j] ^= u[j];
	}

	return out;
}

unsigned char *pbkdf2_hash(
	unsigned char *out,
	unsigned char *(*hmac) (
		unsigned char *out,
		const unsigned char *key,
		size_t key_len,
		const unsigned char *msg,
		size_t msg_len
	),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	int iterations,
	size_t out_size)
{
	int i = 0, len = 0, errsv = 0, out_alloc = 0;
	unsigned char hash_tmp[HASH_DIGEST_SIZE_MAX];

	if (!out) {
		if (!(out = malloc(out_size)))
			return NULL;

		out_alloc = 1;
	}

	for (i = 0, len = 0; (i * hash_len) < out_size; i ++) {
		if (!_f_hash(hash_tmp, hmac, hash_len, pw, pw_len, salt, salt_len, iterations, i + 1)) {
			errsv = errno;
			if (out_alloc) free(out);
			errno = errsv;
			return NULL;
		}

		len = (((i + 1) * hash_len) > out_size) ? out_size - (i * hash_len) : hash_len;

		tc_memcpy(&out[i * hash_len], hash_tmp, len);
	}

	return out;
}

