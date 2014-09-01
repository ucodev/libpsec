/*
 * @file generic.c
 * @brief PSEC Library
 *        AES Encryption/Decryption interface 
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
#include <stdlib.h>

#include "crypt/aes/oaes_lib.h"

unsigned char *aes256cbc_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	int out_alloc = 0;
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Set key */
	if (oaes_key_import_data(ctx, key, 32) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Get output size */
	if (oaes_encrypt(ctx, in, in_len, NULL, out_len) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Allocate output memory if required */
	if (!out) {
		if (!(out = malloc(*out_len)))
			return NULL;

		out_alloc = 1;
	}

	/* Encrypt message */
	if (oaes_encrypt(ctx, in, in_len, out, out_len) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		if (out_alloc) free(out);
		return NULL;
	}

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

