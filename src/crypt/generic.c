/*
 * @file generic.c
 * @brief PSEC Library
 *        Encryption/Decryption interface 
 *
 * Date: 20-08-2014
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

#include "crypt/chacha/generic.h"
#include "crypt/xsalsa20/generic.h"
#include "crypt/otp/generic.h"

unsigned char *crypt_encrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20_encrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_decrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20_decrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_encrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_decrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_encrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return otp_encrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_decrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return otp_decrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_encrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20_encrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_decrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20_decrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_encrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

unsigned char *crypt_decrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

void crypt_destroy(unsigned char *crypt) {
	free(crypt);
}

