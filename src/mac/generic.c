/*
 * @file generic.c
 * @brief PSEC Library
 *        Message Authentication Code interface 
 *
 * Date: 04-09-2014
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

#include "mac/hmac/generic.h"
#include "mac/poly1305/generic.h"

#include "mac.h"

/* HMAC Generic Interface */
unsigned char *mac_hmac_hash(
	unsigned char *out,
	unsigned char *(*hash) (unsigned char *out, const unsigned char *in, size_t in_len),
	size_t hash_len,
	size_t hash_block_size,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_generic(out, hash, hash_len, hash_block_size, key, key_len, msg, msg_len);
}

/* HMAC BLAKE Interface */
unsigned char *mac_hmac_blake224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake224(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_blake256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake256(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_blake384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake384(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_blake512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake512(out, key, key_len, msg, msg_len);
}

/* HMAC BLAKE2 Interface */
unsigned char *mac_hmac_blake2b(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake2b(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_blake2s(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_blake2s(out, key, key_len, msg, msg_len);
}

/* HMAC MD Interface */
unsigned char *mac_hmac_md2(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_md2(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_md4(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_md4(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_md5(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_md5(out, key, key_len, msg, msg_len);
}

/* HMAC RIPEMD Interface */
unsigned char *mac_hmac_ripemd128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_ripemd128(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_ripemd160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_ripemd160(out, key, key_len, msg, msg_len);
}

/* HMAC SHA Interface */
unsigned char *mac_hmac_sha1(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_sha1(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_sha224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_sha224(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_sha256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_sha256(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_sha384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_sha384(out, key, key_len, msg, msg_len);
}

unsigned char *mac_hmac_sha512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_sha512(out, key, key_len, msg, msg_len);
}

/* HMAC RIPEMD Interface */
unsigned char *mac_hmac_whirlpool(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return hmac_whirlpool(out, key, key_len, msg, msg_len);
}

/* Poly1305 Interface */
unsigned char *mac_poly1305_hash(
	unsigned char *out,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len)
{
	return poly1305_auth(out, key, msg, msg_len);
}

int mac_poly1305_verify(
	const unsigned char *mac,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len)
{
	return poly1305_verify(mac, key, msg, msg_len);
}

/* Common interface */
void mac_destroy(unsigned char *digest) {
	free(digest);
}

