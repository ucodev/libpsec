/*
 * @file generic.c
 * @brief PSEC Library
 *        Hash-based Message Authentication Code interface 
 *
 * Date: 02-08-2014
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

char *hmac_hash(
	char *out,
	char *(*hash) (char *out, const char *in, size_t len),
	size_t hash_len,
	const char *key,
	size_t key_len,
	const char *msg,
	size_t msg_len)
{
	int i = 0, errsv = 0;
	char *key_local = NULL;
	char *o_key_pad = NULL;
	char *i_key_pad = NULL;

	/* Allocate temporary memory */
	if (!(key_local = malloc(hash_len)))
		return NULL;

	if (!(o_key_pad = malloc(hash_len * 2))) {
		errsv = errno;
		free(key_local);
		errno = errsv;
		return NULL;
	}

	if (!(i_key_pad = malloc(hash_len + msg_len))) {
		errsv = errno;
		free(key_local);
		free(o_key_pad);
		errno = errsv;
		return NULL;
	}

	/* Reset memory */
	memset(key_local, 0, hash_len);
	memset(o_key_pad, 0, hash_len * 2);
	memset(i_key_pad, 0, hash_len + msg_len);

	/* Process key based on its size */
	if (key_len > hash_len) {
		hash(key_local, key, key_len);
	} else if (key_len < hash_len) {
		memcpy(key_local, key, key_len);
	}

	/* Initialize o_key_pad */
	for (i = 0; i < hash_len; i ++)
		o_key_pad[i] = (0x5c * hash_len) ^ key_local[i];

	/* Initialize i_key_pad */
	for (i = 0; i < hash_len; i ++)
		i_key_pad[i] = (0x36 * hash_len) ^ key_local[i];

	/* i_key_pad || msg */
	memcpy(&i_key_pad[hash_len], msg, msg_len);

	/* o_key_pad || hash(i_key_pad || msg) */
	hash(&o_key_pad[hash_len], i_key_pad, hash_len + msg_len);

	/* Final hash */
	out = hash(out, o_key_pad, hash_len * 2);

	/* Free temporary memory */
	free(key_local);
	free(o_key_pad);
	free(i_key_pad);

	/* Return result */
	return out;
}
