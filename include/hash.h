/*
 * @file hash.h
 * @brief PSEC Library
 *        HASH interface header
 *
 * Date: 22-08-2014
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

#ifndef LIBPSEC_HASH_H
#define LIBPSEC_HASH_H

#include <stdio.h>

/********************/
/* Blake2 Interface */
/********************/
/* DIgest sizes */
#define HASH_DIGEST_SIZE_BLAKE2B	64
#define HASH_DIGEST_SIZE_BLAKE2S	32
#define HASH_BLOCK_SIZE_BLAKE2B		128
#define HASH_BLOCK_SIZE_BLAKE2S		64
/* Prototypes */
unsigned char *hash_buffer_blake2b(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_buffer_blake2s(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_file_blake2b(unsigned char *out, FILE *fp);
unsigned char *hash_file_blake2s(unsigned char *out, FILE *fp);
/*****************/
/* SHA Interface */
/*****************/
/* Digest sizes */
#define HASH_DIGEST_SIZE_SHA1		20
#define HASH_DIGEST_SIZE_SHA224		28
#define HASH_DIGEST_SIZE_SHA256		32
#define HASH_DIGEST_SIZE_SHA384		48
#define HASH_DIGEST_SIZE_SHA512		64
#define HASH_BLOCK_SIZE_SHA1		64
#define HASH_BLOCK_SIZE_SHA224		64
#define HASH_BLOCK_SIZE_SHA256		64
#define HASH_BLOCK_SIZE_SHA384		128
#define HASH_BLOCK_SIZE_SHA512		128
/* Prototypes */
unsigned char *hash_buffer_sha1(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_buffer_sha224(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_buffer_sha256(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_buffer_sha384(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_buffer_sha512(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_file_sha1(unsigned char *out, FILE *fp);
unsigned char *hash_file_sha224(unsigned char *out, FILE *fp);
unsigned char *hash_file_sha256(unsigned char *out, FILE *fp);
unsigned char *hash_file_sha384(unsigned char *out, FILE *fp);
unsigned char *hash_file_sha512(unsigned char *out, FILE *fp);
/****************/
/* MD Interface */
/****************/
/* Digest sizes */
#define HASH_DIGEST_SIZE_MD4		16
#define HASH_DIGEST_SIZE_MD5		16
#define HASH_BLOCK_SIZE_MD4		64
#define HASH_BLOCK_SIZE_MD5		64
/* Prototypes */
unsigned char *hash_buffer_md4(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_file_md4(unsigned char *out, FILE *fp);
unsigned char *hash_buffer_md5(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *hash_file_md5(unsigned char *out, FILE *fp);
/********************/
/* Common Interface */
/********************/
#define HASH_BLOCK_SIZE_MAX		128
#define HASH_DIGEST_SIZE_MAX		64
void hash_destroy(unsigned char *digest);

#endif

