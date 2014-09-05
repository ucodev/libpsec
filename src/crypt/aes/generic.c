/*
 * @file generic.c
 * @brief PSEC Library
 *        AES Encryption/Decryption interface 
 *
 * Date: 05-09-2014
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

#include "crypt/aes/generic.h"
#include "crypt/aes/oaes_lib.h"

static unsigned char *_aes_generic(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key,
	size_t key_len,
	unsigned int encrypt,
	OAES_CTX *ctx)
{
	int out_alloc = 0;

	*out_len = 0;

	/* Set key */
	if (oaes_key_import_data(ctx, key, key_len) != OAES_RET_SUCCESS)
		return NULL;

	/* Get output size */
	if (encrypt) {
		if (oaes_encrypt(ctx, in, in_len, NULL, out_len) != OAES_RET_SUCCESS) {
			return NULL;
		}
	} else {
		if (oaes_decrypt(ctx, in, in_len, NULL, out_len) != OAES_RET_SUCCESS)
			return NULL;
	}

	/* Allocate output memory if required */
	if (!out) {
		if (!(out = malloc(*out_len)))
			return NULL;

		out_alloc = 1;
	}

	/* Encrypt/Decrypt message */
	if (encrypt) {
		if (oaes_encrypt(ctx, in, in_len, out, out_len) != OAES_RET_SUCCESS) {
			if (out_alloc) free(out);
			return NULL;
		}
	} else {
		if (oaes_decrypt(ctx, in, in_len, out, out_len) != OAES_RET_SUCCESS) {
			if (out_alloc) free(out);
			return NULL;
		}
	}

	/* All good */
	return out;
}

unsigned char *aes256cbc_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 32, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes256cbc_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 32, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes256ecb_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 32, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes256ecb_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 32, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}


unsigned char *aes192cbc_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 24, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes192cbc_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 24, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes192ecb_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 24, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes192ecb_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 24, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}


unsigned char *aes128cbc_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 16, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes128cbc_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_CBC, nonce) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 16, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes128ecb_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Encrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 16, 1, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

unsigned char *aes128ecb_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	OAES_CTX *ctx = NULL;

	/* Allocate context */
	if (!(ctx = oaes_alloc()))
		return NULL;

	/* Set IV */
	if (oaes_set_option(ctx, OAES_OPTION_ECB, NULL) != OAES_RET_SUCCESS) {
		oaes_free(&ctx);
		return NULL;
	}

	/* Decrypt message */
	out = _aes_generic(out, out_len, in, in_len, nonce, key, 16, 0, ctx);

	/* Free context */
	oaes_free(&ctx);

	/* All good */
	return out;
}

