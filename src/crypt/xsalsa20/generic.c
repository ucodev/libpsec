/*
 * @file generic.c
 * @brief PSEC Library
 *        Xsalsa20 Encryption/Decryption interface 
 *
 * Date: 08-08-2014
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

#include "crypt/xsalsa20/crypto.h"

unsigned char *xsalsa20_encrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	unsigned char *buf_tmp = NULL;
	unsigned char *in_tmp = NULL, *out_tmp = NULL;

	/* Do a single allocation for both in and out temporary buffers */
	if (!(buf_tmp = malloc((CRYPTO_ZEROBYTES + in_len) * 2)))
		return NULL;

	/* Reset all memory */
	memset(buf_tmp, 0, (CRYPTO_ZEROBYTES + in_len) * 2);

	/* Set the in and out pointers */
	out_tmp = buf_tmp;
	in_tmp = buf_tmp + CRYPTO_ZEROBYTES + in_len;

	/* Copy the input buffer */
	memcpy(in_tmp + CRYPTO_ZEROBYTES, in, in_len);

	/* in_tmp == | zero (32 bytes) | plaintext (in_len) | */

	/* Encrypt data */
	if (crypto_secretbox(out_tmp, in_tmp, in_len + CRYPTO_ZEROBYTES, nonce, key) < 0) {
		free(buf_tmp);
		errno = EINVAL;
		return NULL;
	}

	/* out_tmp == | zero (16 bytes) | poly1305 (16 bytes) | ciphered text (in_len) | */

	/* Craft the respective out buffer */
	if (!out) {
		memmove(buf_tmp, out_tmp + CRYPTO_BOXZEROBYTES, in_len + CRYPTO_POLY1305BYTES);
		out = buf_tmp;
	} else {
		memcpy(out, out_tmp + CRYPTO_BOXZEROBYTES, in_len + CRYPTO_POLY1305BYTES);
		free(buf_tmp);
	}

	*out_len = in_len + CRYPTO_POLY1305BYTES;

	/* All good */
	return out;
}

unsigned char *xsalsa20_decrypt(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	unsigned char *buf_tmp = NULL;
	unsigned char *in_tmp = NULL, *out_tmp = NULL;

	/* Do a single allocation for both in and out temporary buffers */
	if (!(buf_tmp = malloc((CRYPTO_ZEROBYTES + in_len) * 2)))
		return NULL;

	/* Reset all memory */
	memset(buf_tmp, 0, (CRYPTO_ZEROBYTES + in_len) * 2);

	/* Set the in and out pointers */
	out_tmp = buf_tmp;
	in_tmp = buf_tmp + CRYPTO_ZEROBYTES + in_len;

	/* Copy the input buffer */
	memcpy(in_tmp + CRYPTO_BOXZEROBYTES, in, in_len);

	/* in_tmp == | zero (16 bytes) | poly1305 (16 bytes) | ciphertext (in_len - 16 bytes) | */

	/* Decrypt data */
	if (crypto_secretbox_open(out_tmp, in_tmp, in_len + CRYPTO_BOXZEROBYTES, nonce, key) < 0) {
		free(buf_tmp);
		errno = EINVAL;
		return NULL;
	}

	/* out_tmp == | zero (32 bytes) | plaintext (in_len - 16 bytes) | */

	/* Craft the respective out buffer */
	if (!out) {
		memmove(buf_tmp, out_tmp + CRYPTO_ZEROBYTES, in_len - CRYPTO_POLY1305BYTES);
		out = buf_tmp;
	} else {
		memcpy(out, out_tmp + CRYPTO_ZEROBYTES, in_len - CRYPTO_POLY1305BYTES);
		free(buf_tmp);
	}

	if (out_len)
		*out_len = in_len - CRYPTO_POLY1305BYTES;

	/* All good */
	return out;
}

