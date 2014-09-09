/*
 * @file hash.h
 * @brief PSEC Library
 *        KDF interface header
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

#ifndef LIBPSEC_KDF_H
#define LIBPSEC_KDF_H

#include <stdio.h>

#include "mac.h"
#include "hash.h"
#include "hash/low.h"

/* Macros */
/* HKDF */
#define kdf_hkdf_blake224(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake224, HASH_DIGEST_SIZE_BLAKE224, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_blake256(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake256, HASH_DIGEST_SIZE_BLAKE256, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_blake384(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake384, HASH_DIGEST_SIZE_BLAKE384, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_blake512(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake512, HASH_DIGEST_SIZE_BLAKE512, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_blake2b(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake2b, HASH_DIGEST_SIZE_BLAKE2B, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_blake2s(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_blake2s, HASH_DIGEST_SIZE_BLAKE2S, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_gost(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_gost, HASH_DIGEST_SIZE_GOST, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_haval256(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_haval256, HASH_DIGEST_SIZE_HAVAL256, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_haval224(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_haval224, HASH_DIGEST_SIZE_HAVAL224, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_haval192(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_haval192, HASH_DIGEST_SIZE_HAVAL192, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_haval160(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_haval160, HASH_DIGEST_SIZE_HAVAL160, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_haval128(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_haval128, HASH_DIGEST_SIZE_HAVAL128, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_md2(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_md2, HASH_DIGEST_SIZE_MD2, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_md4(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_md4, HASH_DIGEST_SIZE_MD4, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_md5(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_md5, HASH_DIGEST_SIZE_MD5, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_ripemd128(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_ripemd128, HASH_DIGEST_SIZE_RIPEMD128, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_ripemd160(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_ripemd160, HASH_DIGEST_SIZE_RIPEMD160, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_ripemd256(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_ripemd256, HASH_DIGEST_SIZE_RIPEMD256, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_ripemd320(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_ripemd320, HASH_DIGEST_SIZE_RIPEMD320, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_sha1(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_sha1, HASH_DIGEST_SIZE_SHA1, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_sha224(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_sha224, HASH_DIGEST_SIZE_SHA224, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_sha256(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_sha256, HASH_DIGEST_SIZE_SHA256, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_sha384(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_sha384, HASH_DIGEST_SIZE_SHA384, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_sha512(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_sha512, HASH_DIGEST_SIZE_SHA512, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_tiger(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_tiger, HASH_DIGEST_SIZE_TIGER, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_tiger2(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_tiger2, HASH_DIGEST_SIZE_TIGER2, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

#define kdf_hkdf_whirlpool(out, ikm, ikm_len, salt, salt_len, info, info_len, out_len) \
	kdf_hkdf_generic( \
		out, \
		mac_hmac_whirlpool, HASH_DIGEST_SIZE_WHIRLPOOL, \
		ikm, ikm_len, salt, salt_len, info, info_len, out_len)

/* PBKDF1 */
#define kdf_pbkdf1_md2(out, pw, pw_len, salt, iterations, out_size) \
	kdf_pbkdf1_generic( \
		out, \
		hash_low_md2_init, hash_low_md2_update, hash_low_md2_final, HASH_DIGEST_SIZE_MD2, \
		pw, pw_len, salt, iterations, out_size, \
		HASH_DIGEST_SIZE_MD2)

#define kdf_pbkdf1_md5(out, pw, pw_len, salt, iterations, out_size) \
	kdf_pbkdf1_generic( \
		out, \
		hash_low_md5_init, hash_low_md5_update, hash_low_md5_final, HASH_DIGEST_SIZE_MD5, \
		pw, pw_len, salt, iterations, out_size, \
		HASH_DIGEST_SIZE_MD5)

#define kdf_pbkdf1_sha1(out, pw, pw_len, salt, iterations, out_size) \
	kdf_pbkdf1_generic( \
		out, \
		hash_low_sha1_init, hash_low_sha1_update, hash_low_sha1_final, HASH_DIGEST_SIZE_SHA1, \
		pw, pw_len, salt, iterations, out_size, \
		HASH_DIGEST_SIZE_SHA1)

/* PBKDF2 */
#define kdf_pbkdf2_blake224(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake224, HASH_DIGEST_SIZE_BLAKE224, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake256, HASH_DIGEST_SIZE_BLAKE256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake384(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake384, HASH_DIGEST_SIZE_BLAKE384, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake512(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake512, HASH_DIGEST_SIZE_BLAKE512, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake2b(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake2b, HASH_DIGEST_SIZE_BLAKE2B, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_blake2s(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_blake2s, HASH_DIGEST_SIZE_BLAKE2S, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha1(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha1, HASH_DIGEST_SIZE_SHA1, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha224(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha224, HASH_DIGEST_SIZE_SHA224, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha256, HASH_DIGEST_SIZE_SHA256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha384(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha384, HASH_DIGEST_SIZE_SHA384, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_sha512(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_sha512, HASH_DIGEST_SIZE_SHA512, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_gost(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_gost, HASH_DIGEST_SIZE_GOST, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_haval256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_haval256, HASH_DIGEST_SIZE_HAVAL256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_haval224(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_haval224, HASH_DIGEST_SIZE_HAVAL224, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_haval192(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_haval192, HASH_DIGEST_SIZE_HAVAL192, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_haval160(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_haval160, HASH_DIGEST_SIZE_HAVAL160, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_haval128(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_haval128, HASH_DIGEST_SIZE_HAVAL128, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md2(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md2, HASH_DIGEST_SIZE_MD2, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md4(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md4, HASH_DIGEST_SIZE_MD4, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_md5(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_md5, HASH_DIGEST_SIZE_MD5, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd128(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd128, HASH_DIGEST_SIZE_RIPEMD128, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd160(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd160, HASH_DIGEST_SIZE_RIPEMD160, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd256(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd256, HASH_DIGEST_SIZE_RIPEMD256, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_ripemd320(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_ripemd320, HASH_DIGEST_SIZE_RIPEMD320, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_tiger(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_tiger, HASH_DIGEST_SIZE_TIGER, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_tiger2(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_tiger2, HASH_DIGEST_SIZE_TIGER2, \
		pw, pw_len, salt, salt_len, rounds, out_size)

#define kdf_pbkdf2_whirlpool(out, pw, pw_len, salt, salt_len, rounds, out_size) \
	kdf_pbkdf2_generic( \
		out, \
		mac_hmac_whirlpool, HASH_DIGEST_SIZE_WHIRLPOOL, \
		pw, pw_len, salt, salt_len, rounds, out_size)

/* Prototypes */
/* HKDF */
unsigned char *kdf_hkdf_generic(
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
	size_t out_len);

/* PBKDF1 */
unsigned char *kdf_pbkdf1_generic(
	unsigned char *out,
	int (*hash_low_init) (psec_low_hash_t *),
	int (*hash_low_update) (psec_low_hash_t *, const unsigned char *, size_t),
	int (*hash_low_final) (psec_low_hash_t *, unsigned char *),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char salt[8],
	int iterations,
	size_t out_size,
	size_t max_out_size);

/* PBKDF2 */
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
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	int iterations,
	size_t out_size);
void kdf_destroy(unsigned char *digest);

#endif
