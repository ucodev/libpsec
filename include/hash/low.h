/*
 * @file low.h
 * @brief PSEC Library
 *        HASH Low Level interface header
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


#ifndef LIBPSEC_HASH_LOW_H
#define LIBPSEC_HASH_LOW_H

#include "blake2/low.h"
#include "md4/low.h"
#include "md5/low.h"
#include "sha/low.h"

/* Type definitions */
typedef union {
	blake2b_state blake2b;
	blake2s_state blake2s;
	MD4_CTX md4;
	MD5_CTX md5;
	SHA1Context sha1;
	SHA224Context sha224;
	SHA256Context sha256;
	SHA384Context sha384;
	SHA512Context sha512;
} psec_low_hash_t;

/* Prototypes */
/* Blake2b Interface */
int hash_low_blake2b_init(psec_low_hash_t *context);
int hash_low_blake2b_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_blake2b_final(psec_low_hash_t *context, char *out);
/* Blake2s Interface */
int hash_low_blake2s_init(psec_low_hash_t *context);
int hash_low_blake2s_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_blake2s_final(psec_low_hash_t *context, char *out);
/* MD4 Interface */
int hash_low_md4_init(psec_low_hash_t *context);
int hash_low_md4_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_md4_final(psec_low_hash_t *context, char *out);
/* MD5 Interface */
int hash_low_md5_init(psec_low_hash_t *context);
int hash_low_md5_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_md5_final(psec_low_hash_t *context, char *out);
/* SHA1 Interface */
int hash_low_sha1_init(psec_low_hash_t *context);
int hash_low_sha1_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_sha1_final(psec_low_hash_t *context, char *out);
/* SHA224 Interface */
int hash_low_sha224_init(psec_low_hash_t *context);
int hash_low_sha224_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_sha224_final(psec_low_hash_t *context, char *out);
/* SHA256 Interface */
int hash_low_sha256_init(psec_low_hash_t *context);
int hash_low_sha256_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_sha256_final(psec_low_hash_t *context, char *out);
/* SHA384 Interface */
int hash_low_sha384_init(psec_low_hash_t *context);
int hash_low_sha384_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_sha384_final(psec_low_hash_t *context, char *out);
/* SHA512 Interface */
int hash_low_sha512_init(psec_low_hash_t *context);
int hash_low_sha512_update(psec_low_hash_t *context, const char *in, size_t len);
int hash_low_sha512_final(psec_low_hash_t *context, char *out);

#endif

