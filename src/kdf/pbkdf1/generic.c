/*
 * @file generic.c
 * @brief PSEC Library
 *        Password-Based Key Derivation Function 1 interface 
 *
 * Date: 09-09-2014
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

#include "hash.h"
#include "hash/low.h"

unsigned char *pbkdf1_hash(
	unsigned char *out,
	int (*hash_low_init) (psec_low_hash_t *),
	int (*hash_low_update) (psec_low_hash_t *, const unsigned char *, size_t),
	int (*hash_low_final) (psec_low_hash_t *, unsigned char *),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char salt[8],
	int iterations,
	size_t out_size,
	size_t max_out_size)
{
	int i = 0;
	psec_low_hash_t context;
	unsigned char digest[hash_len];

	if (out_size > max_out_size) {
		errno = EINVAL;
		return NULL;
	}

	if (!out) {
		if (!(out = malloc(out_size)))
			return NULL;
	}

	hash_low_init(&context);
	hash_low_update(&context, pw, pw_len);
	hash_low_update(&context, salt, 8);
	hash_low_final(&context, digest);

	for (i = 1; i < iterations; i ++) {
		hash_low_init(&context);
		hash_low_update(&context, digest, hash_len);
		hash_low_final(&context, digest);
	}

	memcpy(out, digest, out_size);

	return out;
}

