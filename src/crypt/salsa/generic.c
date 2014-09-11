/*
 * @file generic.c
 * @brief PSEC Library
 *        Salsa Encryption/Decryption interface 
 *
 * Date: 12-09-2014
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

#include "crypt/salsa/crypto.h"
#include "mac/poly1305/crypto.h"

#include "tc.h"

static unsigned char *_xsalsa_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key,
	unsigned int rounds)
{
	int errsv = 0, out_alloc = 0;

	if (!out) {
		if (!(out = malloc(in_len)))
			return NULL;

		out_alloc = 1;
	}

	if (crypto_stream_xsalsa_xor(out, in, in_len, nonce, key, rounds) < 0) {
		errsv = errno;
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	*out_len = in_len;

	return out;
}

static unsigned char *_xsalsa_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key,
	unsigned int rounds)
{
	return _xsalsa_encrypt(out, out_len, in, in_len, nonce, key, rounds);
}

static unsigned char *_xsalsapoly1305_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key,
	unsigned int rounds)
{
	unsigned char *buf_tmp = NULL;
	unsigned char *in_tmp = NULL, *out_tmp = NULL;

	/* Do a single allocation for both in and out temporary buffers */
	if (!(buf_tmp = malloc((CRYPTO_ZEROBYTES + in_len) * 2)))
		return NULL;

	/* Reset all memory */
	tc_memset(buf_tmp, 0, (CRYPTO_ZEROBYTES + in_len) * 2);

	/* Set the in and out pointers */
	out_tmp = buf_tmp;
	in_tmp = buf_tmp + CRYPTO_ZEROBYTES + in_len;

	/* Copy the input buffer */
	tc_memcpy(in_tmp + CRYPTO_ZEROBYTES, in, in_len);

	/* in_tmp == | zero (32 bytes) | plaintext (in_len) | */

	/* Encrypt data */
	if (crypto_secretbox_xsalsa(out_tmp, in_tmp, in_len + CRYPTO_ZEROBYTES, nonce, key, rounds) < 0) {
		free(buf_tmp);
		errno = EINVAL;
		return NULL;
	}

	/* out_tmp == | zero (16 bytes) | poly1305 (16 bytes) | ciphered text (in_len) | */

	/* Craft the respective out buffer */
	if (!out) {
		tc_memmove(buf_tmp, out_tmp + CRYPTO_BOXZEROBYTES, in_len + CRYPTO_POLY1305BYTES);
		out = buf_tmp;
	} else {
		tc_memcpy(out, out_tmp + CRYPTO_BOXZEROBYTES, in_len + CRYPTO_POLY1305BYTES);
		free(buf_tmp);
	}

	*out_len = in_len + CRYPTO_POLY1305BYTES;

	/* All good */
	return out;
}

static unsigned char *_xsalsapoly1305_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key,
	unsigned int rounds)
{
	unsigned char *buf_tmp = NULL;
	unsigned char *in_tmp = NULL, *out_tmp = NULL;

	/* Do a single allocation for both in and out temporary buffers */
	if (!(buf_tmp = malloc((CRYPTO_ZEROBYTES + in_len) * 2)))
		return NULL;

	/* Reset all memory */
	tc_memset(buf_tmp, 0, (CRYPTO_ZEROBYTES + in_len) * 2);

	/* Set the in and out pointers */
	out_tmp = buf_tmp;
	in_tmp = buf_tmp + CRYPTO_ZEROBYTES + in_len;

	/* Copy the input buffer */
	tc_memcpy(in_tmp + CRYPTO_BOXZEROBYTES, in, in_len);

	/* in_tmp == | zero (16 bytes) | poly1305 (16 bytes) | ciphertext (in_len - 16 bytes) | */

	/* Decrypt data */
	if (crypto_secretbox_xsalsa_open(out_tmp, in_tmp, in_len + CRYPTO_BOXZEROBYTES, nonce, key, rounds) < 0) {
		free(buf_tmp);
		errno = EINVAL;
		return NULL;
	}

	/* out_tmp == | zero (32 bytes) | plaintext (in_len - 16 bytes) | */

	/* Craft the respective out buffer */
	if (!out) {
		tc_memmove(buf_tmp, out_tmp + CRYPTO_ZEROBYTES, in_len - CRYPTO_POLY1305BYTES);
		out = buf_tmp;
	} else {
		tc_memcpy(out, out_tmp + CRYPTO_ZEROBYTES, in_len - CRYPTO_POLY1305BYTES);
		free(buf_tmp);
	}

	if (out_len)
		*out_len = in_len - CRYPTO_POLY1305BYTES;

	/* All good */
	return out;
}

/* Xsalsa20 */
unsigned char *xsalsa20_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_encrypt(out, out_len, in, in_len, nonce, key, 20);
}

unsigned char *xsalsa20_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_decrypt(out, out_len, in, in_len, nonce, key, 20);
}

unsigned char *xsalsa20poly1305_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_encrypt(out, out_len, in, in_len, nonce, key, 20);
}

unsigned char *xsalsa20poly1305_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_decrypt(out, out_len, in, in_len, nonce, key, 20);
}

/* Xsalsa12 */
unsigned char *xsalsa12_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_encrypt(out, out_len, in, in_len, nonce, key, 12);
}

unsigned char *xsalsa12_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_decrypt(out, out_len, in, in_len, nonce, key, 12);
}

unsigned char *xsalsa12poly1305_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_encrypt(out, out_len, in, in_len, nonce, key, 12);
}

unsigned char *xsalsa12poly1305_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_decrypt(out, out_len, in, in_len, nonce, key, 12);
}

/* Xsalsa8 */
unsigned char *xsalsa8_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_encrypt(out, out_len, in, in_len, nonce, key, 8);
}

unsigned char *xsalsa8_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsa_decrypt(out, out_len, in, in_len, nonce, key, 8);
}

unsigned char *xsalsa8poly1305_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_encrypt(out, out_len, in, in_len, nonce, key, 8);
}

unsigned char *xsalsa8poly1305_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return _xsalsapoly1305_decrypt(out, out_len, in, in_len, nonce, key, 8);
}

