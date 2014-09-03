/*
 * @file low.c
 * @brief PSEC Library
 *        HASH Low Level interface 
 *
 * Date: 03-09-2014
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

#include "hash/low.h"

/* Blake2b Interface */
int hash_low_blake2b_init(psec_low_hash_t *context) {
	return blake2b_low_init(&context->blake2b);
}

int hash_low_blake2b_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len) {
	return blake2b_low_init_key(&context->blake2b, key, key_len);
}

int hash_low_blake2b_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake2b_low_update(&context->blake2b, in, in_len);
}

int hash_low_blake2b_final(psec_low_hash_t *context, unsigned char *out) {
	return blake2b_low_final(&context->blake2b, out);
}

/* Blake2s Interface */
int hash_low_blake2s_init(psec_low_hash_t *context) {
	return blake2s_low_init(&context->blake2s);
}

int hash_low_blake2s_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len) {
	return blake2s_low_init_key(&context->blake2s, key, key_len);
}

int hash_low_blake2s_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return blake2s_low_update(&context->blake2s, in, in_len);
}

int hash_low_blake2s_final(psec_low_hash_t *context, unsigned char *out) {
	return blake2s_low_final(&context->blake2s, out);
}

/* MD4 Interface */
int hash_low_md4_init(psec_low_hash_t *context) {
	return md4_low_init(&context->md4);
}

int hash_low_md4_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return md4_low_update(&context->md4, in, in_len);
}

int hash_low_md4_final(psec_low_hash_t *context, unsigned char *out) {
	return md4_low_final(&context->md4, out);
}

/* MD5 Interface */
int hash_low_md5_init(psec_low_hash_t *context) {
	return md5_low_init(&context->md5);
}

int hash_low_md5_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return md5_low_update(&context->md5, in, in_len);
}

int hash_low_md5_final(psec_low_hash_t *context, unsigned char *out) {
	return md5_low_final(&context->md5, out);
}

/* RIPEMD-128 Interface */
int hash_low_ripemd128_init(psec_low_hash_t *context) {
	return ripemd128_low_init(context->ripemd128);
}

int hash_low_ripemd128_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd128_low_update(context->ripemd128, in, in_len);
}

int hash_low_ripemd128_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd128_low_final(context->ripemd128, out);
}

/* RIPEMD-160 Interface */
int hash_low_ripemd160_init(psec_low_hash_t *context) {
	return ripemd160_low_init(context->ripemd160);
}

int hash_low_ripemd160_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return ripemd160_low_update(context->ripemd160, in, in_len);
}

int hash_low_ripemd160_final(psec_low_hash_t *context, unsigned char *out) {
	return ripemd128_low_final(context->ripemd160, out);
}

/* SHA1 Interface */
int hash_low_sha1_init(psec_low_hash_t *context) {
	return sha1_low_init(&context->sha1);
}

int hash_low_sha1_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha1_low_update(&context->sha1, in, in_len);
}

int hash_low_sha1_final(psec_low_hash_t *context, unsigned char *out) {
	return sha1_low_final(&context->sha1, out);
}

/* SHA224 Interface */
int hash_low_sha224_init(psec_low_hash_t *context) {
	return sha224_low_init(&context->sha224);
}

int hash_low_sha224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha224_low_update(&context->sha224, in, in_len);
}

int hash_low_sha224_final(psec_low_hash_t *context, unsigned char *out) {
	return sha224_low_final(&context->sha224, out);
}

/* SHA256 Interface */
int hash_low_sha256_init(psec_low_hash_t *context) {
	return sha256_low_init(&context->sha256);
}

int hash_low_sha256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha256_low_update(&context->sha256, in, in_len);
}

int hash_low_sha256_final(psec_low_hash_t *context, unsigned char *out) {
	return sha256_low_final(&context->sha256, out);
}

/* SHA384 Interface */
int hash_low_sha384_init(psec_low_hash_t *context) {
	return sha384_low_init(&context->sha384);
}

int hash_low_sha384_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha384_low_update(&context->sha384, in, in_len);
}

int hash_low_sha384_final(psec_low_hash_t *context, unsigned char *out) {
	return sha384_low_final(&context->sha384, out);
}

/* SHA512 Interface */
int hash_low_sha512_init(psec_low_hash_t *context) {
	return sha512_low_init(&context->sha512);
}

int hash_low_sha512_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return sha512_low_update(&context->sha512, in, in_len);
}

int hash_low_sha512_final(psec_low_hash_t *context, unsigned char *out) {
	return sha512_low_final(&context->sha512, out);
}

/* WHIRLPOOL Interface */
int hash_low_whirlpool_init(psec_low_hash_t *context) {
	return whirlpool_low_init(&context->whirlpool);
}

int hash_low_whirlpool_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len) {
	return whirlpool_low_update(&context->whirlpool, in, in_len);
}

int hash_low_whirlpool_final(psec_low_hash_t *context, unsigned char *out) {
	return whirlpool_low_final(&context->whirlpool, out);
}

