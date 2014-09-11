/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Derivation Function interface 
 *
 * Date: 11-09-2014
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

#include "hash/low.h"

#include "kdf/bcrypt/generic.h"
#include "kdf/hkdf/generic.h"
#include "kdf/pbkdf1/generic.h"
#include "kdf/pbkdf2/generic.h"
#include "kdf/scrypt/generic.h"

#include "kdf.h"

/* bcrypt */
unsigned char *kdf_bcrypt(
	unsigned char *out,
	unsigned int cost,
	const unsigned char *key,
	size_t key_len,
	const unsigned char salt[16])
{
	return bcrypt_low_do(out, cost, key, key_len, salt);
}

/* HKDF */
unsigned char *kdf_hkdf_generic(
	unsigned char *out,
	unsigned char *(*hmac) (
		unsigned char *out,
		const unsigned char *key,
		size_t key_len,
		const unsigned char *msg,
		size_t msg_len
	),
	size_t hash_len,
	const unsigned char *ikm,
	size_t ikm_len,
	const unsigned char *salt,
	size_t salt_len,
	const unsigned char *info,
	size_t info_len,
	size_t out_len)
{
	return hkdf_expand(out, hmac, hash_len, ikm, ikm_len, salt, salt_len, info, info_len, out_len);
}

/* PBKDF1 Interface */
unsigned char *kdf_pbkdf1_generic(
	unsigned char *out,
	int (*hash_low_init) (psec_low_hash_t *),
	int (*hash_low_update) (psec_low_hash_t *, const unsigned char *, size_t),
	int (*hash_low_final) (psec_low_hash_t *, unsigned char *),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char salt[8],
	int iterations,
	size_t out_size,
	size_t max_out_size)
{
	return pbkdf1_hash(out, hash_low_init, hash_low_update, hash_low_final, hash_len, pw, pw_len, salt, iterations, out_size, max_out_size);
}

/* PBKDF2 Interface */
unsigned char *kdf_pbkdf2_generic(
	unsigned char *out,
	unsigned char *(*hmac) (unsigned char *out, const unsigned char *key, size_t key_len, const unsigned char *msg, size_t msg_len),
	size_t hash_len,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	int iterations,
	size_t out_size)
{
	return pbkdf2_hash(out, hmac, hash_len, pw, pw_len, salt, salt_len, iterations, out_size);
}

/* scrypt */
unsigned char *kdf_scrypt(
	unsigned char *out,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	uint64_t n,
	uint32_t r,
	uint32_t p,
	size_t out_size)
{
	return scrypt_low_do(out, pw, pw_len, salt, salt_len, n, r, p, out_size);
}

/* Common */
void kdf_destroy(unsigned char *digest) {
	free(digest);
}

