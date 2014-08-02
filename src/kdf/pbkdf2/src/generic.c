/*
 * @file generic.c
 * @brief PSEC Library
 *        Password-Based Key Derivation Function 2 interface 
 *
 * Date: 03-08-2014
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

#include <arpa/inet.h>

#include "hmac.h"

static char *_f_hash(
	char *out,
	char *(hash) (char *out, const char *in, size_t len),
	size_t hash_len,
	const char *pw,
	size_t pw_len,
	const char *salt,
	size_t salt_len,
	unsigned int iterations,
	uint32_t iteration)
{
	int i = 0, errsv = 0;
	char *u1 = NULL;
	char *out_tmp = NULL;

	if (!(u1 = malloc(salt_len + 4)))
		return NULL;
	
	if (!(out_tmp = malloc(hash_len))) {
		errsv = errno;
		free(u1);
		errno = errsv;
		return NULL;
	}

	if (!out) {
		if (!(out = malloc(hash_len))) {
			errsv = errno;
			free(u1);
			free(out_tmp);
			errno = errsv;
			return NULL;
		}
	}

	memcpy(u1, salt, salt_len);
	memcpy(&u1[salt_len], (uint32_t [1]) { ntohl(iteration) }, 4);

	hmac_hash(out_tmp, hash, hash_len, pw, pw_len, u1, salt_len + 4);

	free(u1);

	memcpy(out, out_tmp, hash_len);

	for (i = 1; i < iterations; i ++) {
		hmac_hash(out_tmp, hash, hash_len, pw, pw_len, out, hash_len);
		memcpy(out, out_tmp, hash_len);
	}

	free(out_tmp);

	return out;
}

char *pbkdf2_hash(
	char *out,
	char *(hash) (char *out, const char *in, size_t len),
	size_t hash_len,
	const char *pw,
	size_t pw_len,
	const char *salt,
	size_t salt_len,
	int iterations,
	size_t out_size)
{
	int i = 0, len = 0, errsv = 0, out_alloc = 0;
	char *hash_tmp = NULL;

	if (!(hash_tmp = malloc(hash_len)))
		return NULL;

	if (!out) {
		if (!(out = malloc(out_size))) {
			errsv = errno;
			free(hash_tmp);
			errno = errsv;
			return NULL;
		}

		out_alloc = 1;
	}

	for (i = 0, len = hash_len; (i * hash_len) < out_size; i ++) {
		if (!_f_hash(hash_tmp, hash, hash_len, pw, pw_len, salt, salt_len, iterations, i)) {
			errsv = errno;
			free(hash_tmp);
			if (out_alloc) free(out);
			errno = errsv;
			return NULL;
		}

		len = ((i * hash_len) > out_size) ? out_size - (i * hash_len) : hash_len;

		memcpy(&out[i * hash_len], hash_tmp, len);
	}

	free(hash_tmp);

	return out;
}

