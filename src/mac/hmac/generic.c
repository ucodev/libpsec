/*
 * @file generic.c
 * @brief PSEC Library
 *        Hash-based Message Authentication Code interface 
 *
 * Date: 01-09-2014
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
#include <errno.h>
#include <stdlib.h>

#include "hash.h"
#include "tc.h"

unsigned char *hmac_generic(
	unsigned char *out,
	unsigned char *(*hash) (unsigned char *out, const unsigned char *in, size_t in_len),
	size_t hash_len,
	size_t hash_block_size,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	int i = 0;
	unsigned char key_local[HASH_BLOCK_SIZE_MAX];
	unsigned char o_key_pad[HASH_BLOCK_SIZE_MAX + HASH_DIGEST_SIZE_MAX];
	unsigned char *i_key_pad = NULL;

	if (!(i_key_pad = malloc(hash_block_size + msg_len)))
		return NULL;

	/* Reset memory */
	tc_memset(key_local, 0, hash_block_size);
	tc_memset(o_key_pad, 0, hash_block_size + hash_len);
	tc_memset(i_key_pad, 0, hash_block_size + msg_len);

	/* Process key based on its size */
	if (key_len > hash_block_size) {
		hash(key_local, key, key_len);
	} else {
		tc_memcpy(key_local, key, key_len);
	}

	/* Initialize o_key_pad */
	for (i = 0; i < hash_block_size; i ++)
		o_key_pad[i] = key_local[i] ^ 0x5c;

	/* Initialize i_key_pad */
	for (i = 0; i < hash_block_size; i ++)
		i_key_pad[i] = key_local[i] ^ 0x36;

	/* i_key_pad || msg */
	tc_memcpy(&i_key_pad[hash_block_size], msg, msg_len);

	/* o_key_pad || hash(i_key_pad || msg) */
	hash(&o_key_pad[hash_block_size], i_key_pad, hash_block_size + msg_len);

	/* Final hash */
	out = hash(out, o_key_pad, hash_block_size + hash_len);

	/* Free temporary memory */
	free(i_key_pad);

	/* Return result */
	return out;
}

