/*
 * @file generic.c
 * @brief PSEC Library
 *        Hash-based Message Authentication Code interface 
 *
 * Date: 06-09-2014
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

#include "hash/low.h"
#include "hash/blake/low.h"
#include "hash/blake2/low.h"
#include "hash/gost/low.h"
#include "hash/haval/low.h"
#include "hash/md2/low.h"
#include "hash/md4/low.h"
#include "hash/md5/low.h"
#include "hash/ripemd/low.h"
#include "hash/sha/low.h"
#include "hash/tiger/low.h"
#include "hash/whirlpool/low.h"

#include "hash.h"
#include "tc.h"

static unsigned char *_hmac_hash_low_generic(
	unsigned char *(*hash_buffer) (unsigned char *, const unsigned char *, size_t),
	int (*hash_low_init) (psec_low_hash_t *),
	int (*hash_low_update) (psec_low_hash_t *, const unsigned char *, size_t),
	int (*hash_low_final) (psec_low_hash_t *, unsigned char *out),
	size_t hash_block_size,
	size_t hash_digest_size,
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	int i = 0;
	unsigned char key_local[HASH_BLOCK_SIZE_MAX];
	unsigned char o_key_pad[HASH_BLOCK_SIZE_MAX + HASH_DIGEST_SIZE_MAX];
	unsigned char i_key_pad[HASH_BLOCK_SIZE_MAX];
	psec_low_hash_t context;

	/* Reset memory */
	tc_memset(key_local, 0, sizeof(key_local));
	tc_memset(o_key_pad, 0, sizeof(o_key_pad));
	tc_memset(i_key_pad, 0, sizeof(i_key_pad));

	/* Process key based on its size */
	if (key_len > sizeof(key_local)) {
		hash_buffer(key_local, key, key_len);
	} else {
		tc_memcpy(key_local, key, key_len);
	}

	/* Initialize o_key_pad */
	for (i = 0; i < hash_block_size; i ++)
		o_key_pad[i] = key_local[i] ^ 0x5c;

	/* Initialize i_key_pad */
	for (i = 0; i < hash_block_size; i ++)
		i_key_pad[i] = key_local[i] ^ 0x36;

	/* hash(i_key_pad || msg) */
	hash_low_init(&context);
	hash_low_update(&context, i_key_pad, hash_block_size);
	hash_low_update(&context, msg, msg_len);

	/* o_key_pad || hash(i_key_pad || msg) */
	hash_low_final(&context, &o_key_pad[hash_block_size]);

	/* Final hash */
	out = hash_buffer(out, o_key_pad, hash_block_size + hash_digest_size);

	/* Return result */
	return out;
}

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

unsigned char *hmac_blake224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake224, hash_low_blake224_init, hash_low_blake224_update, hash_low_blake224_final, HASH_BLOCK_SIZE_BLAKE224, HASH_DIGEST_SIZE_BLAKE224, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_blake256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake256, hash_low_blake256_init, hash_low_blake256_update, hash_low_blake256_final, HASH_BLOCK_SIZE_BLAKE256, HASH_DIGEST_SIZE_BLAKE256, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_blake384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake384, hash_low_blake384_init, hash_low_blake384_update, hash_low_blake384_final, HASH_BLOCK_SIZE_BLAKE384, HASH_DIGEST_SIZE_BLAKE384, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_blake512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake512, hash_low_blake512_init, hash_low_blake512_update, hash_low_blake512_final, HASH_BLOCK_SIZE_BLAKE512, HASH_DIGEST_SIZE_BLAKE512, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_blake2b(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake2b, hash_low_blake2b_init, hash_low_blake2b_update, hash_low_blake2b_final, HASH_BLOCK_SIZE_BLAKE2B, HASH_DIGEST_SIZE_BLAKE2B, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_blake2s(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_blake2s, hash_low_blake2s_init, hash_low_blake2s_update, hash_low_blake2s_final, HASH_BLOCK_SIZE_BLAKE2S, HASH_DIGEST_SIZE_BLAKE2S, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_gost(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_gost, hash_low_gost_init, hash_low_gost_update, hash_low_gost_final, HASH_BLOCK_SIZE_GOST, HASH_DIGEST_SIZE_GOST, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_haval256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_haval256, hash_low_haval256_init, hash_low_haval256_update, hash_low_haval256_final, HASH_BLOCK_SIZE_HAVAL256, HASH_DIGEST_SIZE_HAVAL256, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_haval224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_haval224, hash_low_haval224_init, hash_low_haval224_update, hash_low_haval224_final, HASH_BLOCK_SIZE_HAVAL224, HASH_DIGEST_SIZE_HAVAL224, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_haval192(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_haval192, hash_low_haval192_init, hash_low_haval192_update, hash_low_haval192_final, HASH_BLOCK_SIZE_HAVAL192, HASH_DIGEST_SIZE_HAVAL192, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_haval160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_haval160, hash_low_haval160_init, hash_low_haval160_update, hash_low_haval160_final, HASH_BLOCK_SIZE_HAVAL160, HASH_DIGEST_SIZE_HAVAL160, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_haval128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_haval128, hash_low_haval128_init, hash_low_haval128_update, hash_low_haval128_final, HASH_BLOCK_SIZE_HAVAL128, HASH_DIGEST_SIZE_HAVAL128, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_md2(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_md2, hash_low_md2_init, hash_low_md2_update, hash_low_md2_final, HASH_BLOCK_SIZE_MD2, HASH_DIGEST_SIZE_MD2, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_md4(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_md4, hash_low_md4_init, hash_low_md4_update, hash_low_md4_final, HASH_BLOCK_SIZE_MD4, HASH_DIGEST_SIZE_MD4, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_md5(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_md5, hash_low_md5_init, hash_low_md5_update, hash_low_md5_final, HASH_BLOCK_SIZE_MD5, HASH_DIGEST_SIZE_MD5, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_ripemd128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_ripemd128, hash_low_ripemd128_init, hash_low_ripemd128_update, hash_low_ripemd128_final, HASH_BLOCK_SIZE_RIPEMD128, HASH_DIGEST_SIZE_RIPEMD128, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_ripemd160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_ripemd160, hash_low_ripemd160_init, hash_low_ripemd160_update, hash_low_ripemd160_final, HASH_BLOCK_SIZE_RIPEMD160, HASH_DIGEST_SIZE_RIPEMD160, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_sha1(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_sha1, hash_low_sha1_init, hash_low_sha1_update, hash_low_sha1_final, HASH_BLOCK_SIZE_SHA1, HASH_DIGEST_SIZE_SHA1, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_sha224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_sha224, hash_low_sha224_init, hash_low_sha224_update, hash_low_sha224_final, HASH_BLOCK_SIZE_SHA224, HASH_DIGEST_SIZE_SHA224, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_sha256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_sha256, hash_low_sha256_init, hash_low_sha256_update, hash_low_sha256_final, HASH_BLOCK_SIZE_SHA256, HASH_DIGEST_SIZE_SHA256, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_sha384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_sha384, hash_low_sha384_init, hash_low_sha384_update, hash_low_sha384_final, HASH_BLOCK_SIZE_SHA384, HASH_DIGEST_SIZE_SHA384, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_sha512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_sha512, hash_low_sha512_init, hash_low_sha512_update, hash_low_sha512_final, HASH_BLOCK_SIZE_SHA512, HASH_DIGEST_SIZE_SHA512, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_tiger(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_tiger, hash_low_tiger_init, hash_low_tiger_update, hash_low_tiger_final, HASH_BLOCK_SIZE_TIGER, HASH_DIGEST_SIZE_TIGER, out, key, key_len, msg, msg_len);
}

unsigned char *hmac_whirlpool(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len)
{
	return _hmac_hash_low_generic(hash_buffer_whirlpool, hash_low_whirlpool_init, hash_low_whirlpool_update, hash_low_whirlpool_final, HASH_BLOCK_SIZE_WHIRLPOOL, HASH_DIGEST_SIZE_WHIRLPOOL, out, key, key_len, msg, msg_len);
}

