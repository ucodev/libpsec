/*
 * @file hash.h
 * @brief PSEC Library
 *        HASH interface header
 *
 * Date: 02-08-2014
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

/*****************/
/* SHA Interface */
/*****************/
/* Digest sizes */
#define HASH_DIGEST_SIZE_SHA1		20
#define HASH_DIGEST_SIZE_SHA224		28
#define HASH_DIGEST_SIZE_SHA256		32
#define HASH_DIGEST_SIZE_SHA384		48
#define HASH_DIGEST_SIZE_SHA512		64
#define HASH_FMT_DIGEST_SIZE_SHA1	((HASH_DIGEST_SIZE_SHA1 * 2) + 1)
#define HASH_FMT_DIGEST_SIZE_SHA224	((HASH_DIGEST_SIZE_SHA224 * 2) + 1)
#define HASH_FMT_DIGEST_SIZE_SHA256	((HASH_DIGEST_SIZE_SHA256 * 2) + 1)
#define HASH_FMT_DIGEST_SIZE_SHA384	((HASH_DIGEST_SIZE_SHA384 * 2) + 1)
#define HASH_FMT_DIGEST_SIZE_SHA512	((HASH_DIGEST_SIZE_SHA512 * 2) + 1)
/* Prototypes */
char *hash_buffer_sha1(char *out, const char *in, size_t len);
char *hash_buffer_sha224(char *out, const char *in, size_t len);
char *hash_buffer_sha256(char *out, const char *in, size_t len);
char *hash_buffer_sha384(char *out, const char *in, size_t len);
char *hash_buffer_sha512(char *out, const char *in, size_t len);
char *hash_file_sha1(char *out, FILE *fp);
char *hash_file_sha224(char *out, FILE *fp);
char *hash_file_sha256(char *out, FILE *fp);
char *hash_file_sha384(char *out, FILE *fp);
char *hash_file_sha512(char *out, FILE *fp);
/****************/
/* MD Interface */
/****************/
/* Digest sizes */
#define HASH_DIGEST_SIZE_MD5		16
#define HASH_FMT_DIGEST_SIZE_MD5	((HASH_DIGEST_SIZE_MD5 * 2) + 1)
/* Prototypes */
char *hash_buffer_md5(char *out, const char *in, size_t len);
char *hash_file_md5(char *out, FILE *fp);
/************************/
/* Formatting Interface */
/************************/
char *hash_format_hex(char *out, const char *digest, size_t len);
void hash_format_destroy(char *fmt_digest);
/*********************/
/* Generic Interface */
/*********************/
void hash_destroy(char *digest);

#endif

