/*
 * @file low.c
 * @brief PSEC Library
 *        HASH Low Level interface 
 *
 * Date: 16-01-2015
 *
 * Copyright 2014-2015 Pedro A. Hortas (pah@ucodev.org)
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

#include "config.h"

#include "hash/low.h"

/* BLAKE-224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_init(psec_low_hash_t *context) {
	return blake224_low_init(&context->blake224);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake224_low_update(&context->blake224, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_final(psec_low_hash_t *context, unsigned char *out) {
	return blake224_low_final(&context->blake224, out);
}

/* BLAKE-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_init(psec_low_hash_t *context) {
	return blake256_low_init(&context->blake256);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake256_low_update(&context->blake256, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_final(psec_low_hash_t *context, unsigned char *out) {
	return blake256_low_final(&context->blake256, out);
}

/* BLAKE-384 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_init(psec_low_hash_t *context) {
	return blake384_low_init(&context->blake384);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake384_low_update(&context->blake384, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_final(psec_low_hash_t *context, unsigned char *out) {
	return blake384_low_final(&context->blake384, out);
}

/* BLAKE-512 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_init(psec_low_hash_t *context) {
	return blake512_low_init(&context->blake512);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake512_low_update(&context->blake512, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_final(psec_low_hash_t *context, unsigned char *out) {
	return blake512_low_final(&context->blake512, out);
}

/* Blake2b Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_init(psec_low_hash_t *context) {
	return blake2b_low_init(&context->blake2b);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len) {
	return blake2b_low_init_key(&context->blake2b, key, key_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake2b_low_update(&context->blake2b, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_final(psec_low_hash_t *context, unsigned char *out) {
	return blake2b_low_final(&context->blake2b, out);
}

/* Blake2s Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_init(psec_low_hash_t *context) {
	return blake2s_low_init(&context->blake2s);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len) {
	return blake2s_low_init_key(&context->blake2s, key, key_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake2s_low_update(&context->blake2s, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_final(psec_low_hash_t *context, unsigned char *out) {
	return blake2s_low_final(&context->blake2s, out);
}

/* GOST Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_init(psec_low_hash_t *context) {
	return gost_low_init(&context->gost);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return gost_low_update(&context->gost, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_final(psec_low_hash_t *context, unsigned char *out) {
	return gost_low_final(&context->gost, out);
}

/* HAVAL-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_init(psec_low_hash_t *context) {
	return haval256_low_init(&context->haval);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_init_passes(psec_low_hash_t *context, unsigned int passes) {
	return haval256_low_init_passes(&context->haval, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return haval256_low_update(&context->haval, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_final(psec_low_hash_t *context, unsigned char *out) {
	return haval256_low_final(&context->haval, out);
}

/* HAVAL-224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_init(psec_low_hash_t *context) {
	return haval224_low_init(&context->haval);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_init_passes(psec_low_hash_t *context, unsigned int passes) {
	return haval224_low_init_passes(&context->haval, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return haval224_low_update(&context->haval, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_final(psec_low_hash_t *context, unsigned char *out) {
	return haval224_low_final(&context->haval, out);
}

/* HAVAL-192 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_init(psec_low_hash_t *context) {
	return haval192_low_init(&context->haval);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_init_passes(psec_low_hash_t *context, unsigned int passes) {
	return haval192_low_init_passes(&context->haval, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return haval192_low_update(&context->haval, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_final(psec_low_hash_t *context, unsigned char *out) {
	return haval192_low_final(&context->haval, out);
}

/* HAVAL-160 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_init(psec_low_hash_t *context) {
	return haval160_low_init(&context->haval);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_init_passes(psec_low_hash_t *context, unsigned int passes) {
	return haval160_low_init_passes(&context->haval, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return haval160_low_update(&context->haval, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_final(psec_low_hash_t *context, unsigned char *out) {
	return haval160_low_final(&context->haval, out);
}

/* HAVAL-128 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_init(psec_low_hash_t *context) {
	return haval128_low_init(&context->haval);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_init_passes(psec_low_hash_t *context, unsigned int passes) {
	return haval128_low_init_passes(&context->haval, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return haval128_low_update(&context->haval, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_final(psec_low_hash_t *context, unsigned char *out) {
	return haval128_low_final(&context->haval, out);
}

/* MD2 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_init(psec_low_hash_t *context) {
	return md2_low_init(&context->md2);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return md2_low_update(&context->md2, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_final(psec_low_hash_t *context, unsigned char *out) {
	return md2_low_final(&context->md2, out);
}

/* MD4 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_init(psec_low_hash_t *context) {
	return md4_low_init(&context->md4);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return md4_low_update(&context->md4, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_final(psec_low_hash_t *context, unsigned char *out) {
	return md4_low_final(&context->md4, out);
}

/* MD5 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_init(psec_low_hash_t *context) {
	return md5_low_init(&context->md5);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return md5_low_update(&context->md5, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_final(psec_low_hash_t *context, unsigned char *out) {
	return md5_low_final(&context->md5, out);
}

/* RIPEMD-128 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_init(psec_low_hash_t *context) {
	return ripemd128_low_init(&context->ripemd128);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd128_low_update(&context->ripemd128, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd128_low_final(&context->ripemd128, out);
}

/* RIPEMD-160 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_init(psec_low_hash_t *context) {
	return ripemd160_low_init(&context->ripemd160);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd160_low_update(&context->ripemd160, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd160_low_final(&context->ripemd160, out);
}

/* RIPEMD-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_init(psec_low_hash_t *context) {
	return ripemd256_low_init(&context->ripemd256);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd256_low_update(&context->ripemd256, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd256_low_final(&context->ripemd256, out);
}

/* RIPEMD-320 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_init(psec_low_hash_t *context) {
	return ripemd320_low_init(&context->ripemd320);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd320_low_update(&context->ripemd320, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd320_low_final(&context->ripemd320, out);
}

/* SHA1 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_init(psec_low_hash_t *context) {
	return sha1_low_init(&context->sha1);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha1_low_update(&context->sha1, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_final(psec_low_hash_t *context, unsigned char *out) {
	return sha1_low_final(&context->sha1, out);
}

/* SHA224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_init(psec_low_hash_t *context) {
	return sha224_low_init(&context->sha224);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha224_low_update(&context->sha224, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_final(psec_low_hash_t *context, unsigned char *out) {
	return sha224_low_final(&context->sha224, out);
}

/* SHA256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_init(psec_low_hash_t *context) {
	return sha256_low_init(&context->sha256);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha256_low_update(&context->sha256, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_final(psec_low_hash_t *context, unsigned char *out) {
	return sha256_low_final(&context->sha256, out);
}

/* SHA384 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_init(psec_low_hash_t *context) {
	return sha384_low_init(&context->sha384);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha384_low_update(&context->sha384, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_final(psec_low_hash_t *context, unsigned char *out) {
	return sha384_low_final(&context->sha384, out);
}

/* SHA512 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_init(psec_low_hash_t *context) {
	return sha512_low_init(&context->sha512);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha512_low_update(&context->sha512, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_final(psec_low_hash_t *context, unsigned char *out) {
	return sha512_low_final(&context->sha512, out);
}

/* TIGER Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_init(psec_low_hash_t *context) {
	return tiger_low_init(&context->tiger);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_set_passes(psec_low_hash_t *context, unsigned int passes) {
	return tiger_low_set_passes(&context->tiger, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return tiger_low_update(&context->tiger, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_final(psec_low_hash_t *context, unsigned char *out) {
	return tiger_low_final(&context->tiger, out);
}

/* TIGER2 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_init(psec_low_hash_t *context) {
	return tiger2_low_init(&context->tiger2);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_set_passes(psec_low_hash_t *context, unsigned int passes) {
	return tiger2_low_set_passes(&context->tiger2, passes);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return tiger2_low_update(&context->tiger2, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_final(psec_low_hash_t *context, unsigned char *out) {
	return tiger2_low_final(&context->tiger2, out);
}

/* WHIRLPOOL Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_init(psec_low_hash_t *context) {
	return whirlpool_low_init(&context->whirlpool);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return whirlpool_low_update(&context->whirlpool, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_final(psec_low_hash_t *context, unsigned char *out) {
	return whirlpool_low_final(&context->whirlpool, out);
}

