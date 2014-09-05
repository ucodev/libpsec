/*
 * @file hash.h
 * @brief PSEC Library
 *        KDF interface header
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

#ifndef LIBPSEC_KDF_H
#define LIBPSEC_KDF_H

#include <stdio.h>

#include "hash.h"

/* Macros */
#define kdf_pbkdf2_blake224(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake224, HASH_DIGEST_SIZE_BLAKE224, HASH_BLOCK_SIZE_BLAKE224, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake256, HASH_DIGEST_SIZE_BLAKE256, HASH_BLOCK_SIZE_BLAKE256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake384(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake384, HASH_DIGEST_SIZE_BLAKE384, HASH_BLOCK_SIZE_BLAKE384, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake512(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake512, HASH_DIGEST_SIZE_BLAKE512, HASH_BLOCK_SIZE_BLAKE512, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake2b(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake2b, HASH_DIGEST_SIZE_BLAKE2B, HASH_BLOCK_SIZE_BLAKE2B, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake2s(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake2s, HASH_DIGEST_SIZE_BLAKE2S, HASH_BLOCK_SIZE_BLAKE2S, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha1(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha1, HASH_DIGEST_SIZE_SHA1, HASH_BLOCK_SIZE_SHA1, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha224(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha224, HASH_DIGEST_SIZE_SHA224, HASH_BLOCK_SIZE_SHA224, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha256, HASH_DIGEST_SIZE_SHA256, HASH_BLOCK_SIZE_SHA256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha384(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha384, HASH_DIGEST_SIZE_SHA384, HASH_BLOCK_SIZE_SHA384, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha512(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_gost(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_gost, HASH_DIGEST_SIZE_GOST, HASH_BLOCK_SIZE_GOST, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md2(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md2, HASH_DIGEST_SIZE_MD2, HASH_BLOCK_SIZE_MD2, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md4(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md4, HASH_DIGEST_SIZE_MD4, HASH_BLOCK_SIZE_MD4, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md5(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md5, HASH_DIGEST_SIZE_MD5, HASH_BLOCK_SIZE_MD5, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd128(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd128, HASH_DIGEST_SIZE_RIPEMD128, HASH_BLOCK_SIZE_RIPEMD128, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd160(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd160, HASH_DIGEST_SIZE_RIPEMD160, HASH_BLOCK_SIZE_RIPEMD160, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_whirlpool(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_whirlpool, HASH_DIGEST_SIZE_WHIRLPOOL, HASH_BLOCK_SIZE_WHIRLPOOL, \
		pw, pw_len, salt, salt_len, rounds, out_size)

/* Prototypes */
unsigned char *kdf_pbkdf2_generic(
	unsigned char *out,
	unsigned char *(*hmac) (
		unsigned char *out,
		const unsigned char *key,
		size_t key_len,
		const unsigned char *msg,
		size_t msg_len
	),
	size_t hash_len,
	size_t hash_block_size,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	int iterations,
	size_t out_size);
void kdf_destroy(unsigned char *digest);

#endif
