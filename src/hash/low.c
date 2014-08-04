/*
 * @file low.c
 * @brief PSEC Library
 *        HASH Low Level interface 
 *
 * Date: 04-08-2014
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

/* MD4 Interface */
int hash_low_md4_init(psec_low_hash_t *context) {
	return md4_low_init(&context->md4);
}

int hash_low_md4_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return md4_low_compress(&context->md4, in, len);
}

int hash_low_md4_final(psec_low_hash_t *context, char *out) {
	return md4_low_final(&context->md4, out);
}

/* MD5 Interface */
int hash_low_md5_init(psec_low_hash_t *context) {
	return md5_low_init(&context->md5);
}

int hash_low_md5_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return md5_low_compress(&context->md5, in, len);
}

int hash_low_md5_final(psec_low_hash_t *context, char *out) {
	return md5_low_final(&context->md5, out);
}

/* SHA1 Interface */
int hash_low_sha1_init(psec_low_hash_t *context) {
	return sha1_low_init(&context->sha1);
}

int hash_low_sha1_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return sha1_low_compress(&context->sha1, in, len);
}

int hash_low_sha1_final(psec_low_hash_t *context, char *out) {
	return sha1_low_final(&context->sha1, out);
}

/* SHA224 Interface */
int hash_low_sha224_init(psec_low_hash_t *context) {
	return sha224_low_init(&context->sha224);
}

int hash_low_sha224_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return sha224_low_compress(&context->sha224, in, len);
}

int hash_low_sha224_final(psec_low_hash_t *context, char *out) {
	return sha224_low_final(&context->sha224, out);
}

/* SHA256 Interface */
int hash_low_sha256_init(psec_low_hash_t *context) {
	return sha256_low_init(&context->sha256);
}

int hash_low_sha256_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return sha256_low_compress(&context->sha256, in, len);
}

int hash_low_sha256_final(psec_low_hash_t *context, char *out) {
	return sha256_low_final(&context->sha256, out);
}

/* SHA384 Interface */
int hash_low_sha384_init(psec_low_hash_t *context) {
	return sha384_low_init(&context->sha384);
}

int hash_low_sha384_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return sha384_low_compress(&context->sha384, in, len);
}

int hash_low_sha384_final(psec_low_hash_t *context, char *out) {
	return sha384_low_final(&context->sha384, out);
}

/* SHA512 Interface */
int hash_low_sha512_init(psec_low_hash_t *context) {
	return sha512_low_init(&context->sha512);
}

int hash_low_sha512_compress(psec_low_hash_t *context, const char *in, size_t len) {
	return sha512_low_compress(&context->sha512, in, len);
}

int hash_low_sha512_final(psec_low_hash_t *context, char *out) {
	return sha512_low_final(&context->sha512, out);
}

