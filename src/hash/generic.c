/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH interface 
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

#include "hash/blake/generic.h"
#include "hash/blake2/generic.h"
#include "hash/gost/generic.h"
#include "hash/md2/generic.h"
#include "hash/md4/generic.h"
#include "hash/md5/generic.h"
#include "hash/ripemd/generic.h"
#include "hash/sha/generic.h"
#include "hash/whirlpool/generic.h"

#include "hash.h"

/* MD Interface */
unsigned char *hash_buffer_md2(unsigned char *out, const unsigned char *in, size_t in_len) {
	return md2_buffer(out, in, in_len);
}

unsigned char *hash_file_md2(unsigned char *out, FILE *fp) {
	return md2_file(out, fp);
}

unsigned char *hash_buffer_md4(unsigned char *out, const unsigned char *in, size_t in_len) {
	return md4_buffer(out, in, in_len);
}

unsigned char *hash_file_md4(unsigned char *out, FILE *fp) {
	return md4_file(out, fp);
}

unsigned char *hash_buffer_md5(unsigned char *out, const unsigned char *in, size_t in_len) {
	return md5_buffer(out, in, in_len);
}

unsigned char *hash_file_md5(unsigned char *out, FILE *fp) {
	return md5_file(out, fp);
}

/* GOST Interface */
unsigned char *hash_buffer_gost(unsigned char *out, const unsigned char *in, size_t in_len) {
	return gost_buffer(out, in, in_len);
}

/* RIPEMD Interface */
unsigned char *hash_buffer_ripemd128(unsigned char *out, const unsigned char *in, size_t in_len) {
	return ripemd128_buffer(out, in, in_len);
}

unsigned char *hash_file_ripemd128(unsigned char *out, FILE *fp) {
	return ripemd128_file(out, fp);
}

unsigned char *hash_buffer_ripemd160(unsigned char *out, const unsigned char *in, size_t in_len) {
	return ripemd160_buffer(out, in, in_len);
}

unsigned char *hash_file_ripemd160(unsigned char *out, FILE *fp) {
	return ripemd160_file(out, fp);
}

/* SHA Interface */
unsigned char *hash_buffer_sha1(unsigned char *out, const unsigned char *in, size_t in_len) {
	return sha1_buffer(out, in, in_len);
}

unsigned char *hash_file_sha1(unsigned char *out, FILE *fp) {
	return sha1_file(out, fp);
}

unsigned char *hash_buffer_sha224(unsigned char *out, const unsigned char *in, size_t in_len) {
	return sha224_buffer(out, in, in_len);
}

unsigned char *hash_file_sha224(unsigned char *out, FILE *fp) {
	return sha224_file(out, fp);
}

unsigned char *hash_buffer_sha256(unsigned char *out, const unsigned char *in, size_t in_len) {
	return sha256_buffer(out, in, in_len);
}

unsigned char *hash_file_sha256(unsigned char *out, FILE *fp) {
	return sha256_file(out, fp);
}

unsigned char *hash_buffer_sha384(unsigned char *out, const unsigned char *in, size_t in_len) {
	return sha384_buffer(out, in, in_len);
}

unsigned char *hash_file_sha384(unsigned char *out, FILE *fp) {
	return sha384_file(out, fp);
}

unsigned char *hash_buffer_sha512(unsigned char *out, const unsigned char *in, size_t in_len) {
	return sha512_buffer(out, in, in_len);
}

unsigned char *hash_file_sha512(unsigned char *out, FILE *fp) {
	return sha512_file(out, fp);
}

/* BLAKE Interface */
unsigned char *hash_buffer_blake224(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake224_buffer(out, in, in_len);
}

unsigned char *hash_file_blake224(unsigned char *out, FILE *fp) {
	return blake224_file(out, fp);
}

unsigned char *hash_buffer_blake256(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake256_buffer(out, in, in_len);
}

unsigned char *hash_file_blake256(unsigned char *out, FILE *fp) {
	return blake256_file(out, fp);
}

unsigned char *hash_buffer_blake384(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake384_buffer(out, in, in_len);
}

unsigned char *hash_file_blake384(unsigned char *out, FILE *fp) {
	return blake384_file(out, fp);
}

unsigned char *hash_buffer_blake512(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake512_buffer(out, in, in_len);
}

unsigned char *hash_file_blake512(unsigned char *out, FILE *fp) {
	return blake512_file(out, fp);
}

/* Keyed Blake2 Interface */
unsigned char *hash_buffer_blake2b_key(unsigned char *out, const unsigned char *in, size_t in_len, const unsigned char *key, size_t key_len) {
	return blake2b_buffer(out, in, in_len, key, key_len);
}

unsigned char *hash_file_blake2b_key(unsigned char *out, FILE *fp, const unsigned char *key, size_t key_len) {
	return blake2b_file(out, fp, key, key_len);
}

unsigned char *hash_buffer_blake2s_key(unsigned char *out, const unsigned char *in, size_t in_len, const unsigned char *key, size_t key_len) {
	return blake2s_buffer(out, in, in_len, key, key_len);
}

unsigned char *hash_file_blake2s_key(unsigned char *out, FILE *fp, const unsigned char *key, size_t key_len) {
	return blake2s_file(out, fp, key, key_len);
}

/* Blake2 Interface */
unsigned char *hash_buffer_blake2b(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake2b_buffer(out, in, in_len, NULL, 0);
}

unsigned char *hash_file_blake2b(unsigned char *out, FILE *fp) {
	return blake2b_file(out, fp, NULL, 0);
}

unsigned char *hash_buffer_blake2s(unsigned char *out, const unsigned char *in, size_t in_len) {
	return blake2s_buffer(out, in, in_len, NULL, 0);
}

unsigned char *hash_file_blake2s(unsigned char *out, FILE *fp) {
	return blake2s_file(out, fp, NULL, 0);
}

/* WHIRLPOOL Interface */
unsigned char *hash_buffer_whirlpool(unsigned char *out, const unsigned char *in, size_t in_len) {
	return whirlpool_buffer(out, in, in_len);
}

unsigned char *hash_file_whirlpool(unsigned char *out, FILE *fp) {
	return whirlpool_file(out, fp);
}

/* Generic */
void hash_destroy(unsigned char *digest) {
	free(digest);
}

