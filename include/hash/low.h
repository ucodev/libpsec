/*
 * @file low.h
 * @brief PSEC Library
 *        HASH Low Level interface header
 *
 * Date: 16-03-2015
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


#ifndef LIBPSEC_HASH_LOW_H
#define LIBPSEC_HASH_LOW_H

#include <stdint.h>

#include "../config.h"

#include "blake/low.h"
#include "blake2/low.h"
#include "gost/low.h"
#include "haval/low.h"
#include "md2/low.h"
#include "md4/low.h"
#include "md5/low.h"
#include "ripemd/low.h"
#include "sha/low.h"
#include "tiger/low.h"
#include "whirlpool/low.h"

/* Type definitions */
typedef union {
	state224 blake224;
	state256 blake256;
	state384 blake384;
	state512 blake512;
	blake2b_state blake2b;
	blake2s_state blake2s;
	GostHashCtx gost;
	haval_state haval;
	MD2_CTX md2;
	MD4_CTX md4;
	MD5_CTX md5;
	ripemd128_state ripemd128;
	ripemd160_state ripemd160;
	ripemd256_state ripemd256;
	ripemd320_state ripemd320;
	SHA1Context sha1;
	SHA224Context sha224;
	SHA256Context sha256;
	SHA384Context sha384;
	SHA512Context sha512;
	tiger_state tiger;
	tiger_state tiger2;
	struct NESSIEstruct whirlpool;
} psec_low_hash_t;

/* Prototypes */
/* BLAKE-224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake224_final(psec_low_hash_t *context, unsigned char *out);
/* BLAKE-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake256_final(psec_low_hash_t *context, unsigned char *out);
/* BLAKE-384 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake384_final(psec_low_hash_t *context, unsigned char *out);
/* BLAKE-512 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake512_final(psec_low_hash_t *context, unsigned char *out);
/* Blake2b Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2b_final(psec_low_hash_t *context, unsigned char *out);
/* Blake2s Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_init_key(psec_low_hash_t *context, const unsigned char *key, size_t key_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_blake2s_final(psec_low_hash_t *context, unsigned char *out);
/* GOST Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_gost_final(psec_low_hash_t *context, unsigned char *out);
/* HAVAL-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval256_final(psec_low_hash_t *context, unsigned char *out);
/* HAVAL-224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval224_final(psec_low_hash_t *context, unsigned char *out);
/* HAVAL-192 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval192_final(psec_low_hash_t *context, unsigned char *out);
/* HAVAL-160 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval160_final(psec_low_hash_t *context, unsigned char *out);
/* HAVAL-128 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_haval128_final(psec_low_hash_t *context, unsigned char *out);
/* MD2 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md2_final(psec_low_hash_t *context, unsigned char *out);
/* MD4 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md4_final(psec_low_hash_t *context, unsigned char *out);
/* MD5 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_md5_final(psec_low_hash_t *context, unsigned char *out);
/* RIPEMD-128 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd128_final(psec_low_hash_t *context, unsigned char *out);
/* RIPEMD-160 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd160_final(psec_low_hash_t *context, unsigned char *out);
/* RIPEMD-256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd256_final(psec_low_hash_t *context, unsigned char *out);
/* RIPEMD-320 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_ripemd320_final(psec_low_hash_t *context, unsigned char *out);
/* SHA1 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha1_final(psec_low_hash_t *context, unsigned char *out);
/* SHA224 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha224_final(psec_low_hash_t *context, unsigned char *out);
/* SHA256 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha256_final(psec_low_hash_t *context, unsigned char *out);
/* SHA384 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha384_final(psec_low_hash_t *context, unsigned char *out);
/* SHA512 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_sha512_final(psec_low_hash_t *context, unsigned char *out);
/* TIGER Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger_final(psec_low_hash_t *context, unsigned char *out);
/* TIGER2 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_init_passes(psec_low_hash_t *context, unsigned int passes);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_tiger2_final(psec_low_hash_t *context, unsigned char *out);
/* WHIRLPOOL Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_init(psec_low_hash_t *context);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_update(psec_low_hash_t *context, const unsigned char *in, size_t in_len);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int hash_low_whirlpool_final(psec_low_hash_t *context, unsigned char *out);

#endif

