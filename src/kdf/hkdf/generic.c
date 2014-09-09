/*
 * @file generic.c
 * @brief PSEC Library
 *        HMAC-based Extract-and-Expand Key Derivation Function interface 
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
#include "mac.h"
#include "tc.h"

unsigned char *hkdf_expand(
	unsigned char *out,
	unsigned char *(*hmac) (
		unsigned char *out,
		const unsigned char *key,
		size_t key_len,
		const unsigned char *msg,
		size_t msg_len
	),
	size_t hash_len,
	const unsigned char *ikm,
	size_t ikm_len,
	const unsigned char *salt,
	size_t salt_len,
	const unsigned char *info,
	size_t info_len,
	size_t out_len)
{
	unsigned int i = 0;
	float nf = ((float) out_len / (float) hash_len);
	unsigned int n = ((nf - ((float) ((unsigned int) nf))) > 0) ? ((unsigned int) nf) + 1 : ((unsigned int) nf);
	unsigned char prk[HASH_DIGEST_SIZE_MAX];
	unsigned char t[hash_len + info_len + 1];
	unsigned char o_tmp[n * hash_len];

	/* Validate */
	if (out_len > (255 * hash_len)) {
		errno = EINVAL;
		return NULL;
	}

	/* Extract */
	if (!hmac(prk, salt, salt_len, ikm, ikm_len))
		return NULL;

	/* Expand */
	if (info_len)
		tc_memcpy(t, info, info_len);

	t[info_len] = 0x01;

	if (!hmac(o_tmp, prk, hash_len, t, info_len + 1))
		return NULL;

	for (i = 2; i <= n; i ++) {
		tc_memcpy(t, &o_tmp[(i - 2) * hash_len], hash_len);

		if (info_len)
			tc_memcpy(&t[hash_len], info, info_len);

		t[hash_len + info_len] = (unsigned char) i;

		if (!hmac(&o_tmp[(i - 1) * hash_len], prk, hash_len, t, sizeof(t)))
			return NULL;
	}

	/* Allocate */
	if (!out) {
		if (!(out = malloc(out_len)))
			return NULL;
	}

	/* Deliver */
	tc_memcpy(out, o_tmp, out_len);

	/* All good */
	return out;
}

