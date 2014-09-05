/*
 * @file generic.h
 * @brief PSEC Library
 *        Hash-based Message Authentication Code interface header
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

#ifndef LIBPSEC_GENERIC_HMAC_H
#define LIBPSEC_GENERIC_HMAC_H

#include <stdio.h>


/* Prototypes */
/**************************/
/* HMAC Generic Interface */
/**************************/
unsigned char *hmac_generic(
	unsigned char *out,
	unsigned char *(*hash) (unsigned char *out, const unsigned char *in, size_t in_len),
	size_t hash_len,
	size_t hash_block_size,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/************************/
/* HMAC BLAKE Interface */
/************************/
unsigned char *hmac_blake224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_blake256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_blake384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_blake512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*************************/
/* HMAC BLAKE2 Interface */
/*************************/
unsigned char *hmac_blake2b(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_blake2s(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/***********************/
/* HMAC GOST Interface */
/***********************/
unsigned char *hmac_gost(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*********************/
/* HMAC MD Interface */
/*********************/
unsigned char *hmac_md2(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_md4(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_md5(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*************************/
/* HMAC RIPEMD Interface */
/*************************/
unsigned char *hmac_ripemd128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_ripemd160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/**********************/
/* HMAC SHA Interface */
/**********************/
unsigned char *hmac_sha1(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_sha224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_sha256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_sha384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *hmac_sha512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/****************************/
/* HMAC WHIRLPOOL Interface */
/****************************/
unsigned char *hmac_whirlpool(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);

#endif

