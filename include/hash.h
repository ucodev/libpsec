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
/* Prototypes */
char *hash_sha1_create(const char *in, size_t len);
char *hash_sha224_create(const char *in, size_t len);
char *hash_sha256_create(const char *in, size_t len);
char *hash_sha384_create(const char *in, size_t len);
char *hash_sha512_create(const char *in, size_t len);
void hash_sha1_destroy(char *digest);
void hash_sha224_destroy(char *digest);
void hash_sha256_destroy(char *digest);
void hash_sha384_destroy(char *digest);
void hash_sha512_destroy(char *digest);
/****************/
/* MD Interface */
/****************/
/* Digest sizes */
#define HASH_DIGEST_SIZE_MD5		16
/* Prototypes */
char *hash_md5_create(const char *in, size_t len);
void hash_md5_destroy(char *digest);
/************************/
/* Formatting Interface */
/************************/
char *hash_format_create_hex(const char *digest, size_t len);
void hash_format_destroy(char *fmt_digest);

#endif

