/*
 * @file mac.h
 * @brief PSEC Library
 *        MAC interface header
 *
 * Date: 06-09-2014
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

#ifndef LIBPSEC_MAC_H
#define LIBPSEC_MAC_H

#include <stdio.h>

/* Prototypes */
/**************************/
/* HMAC Generic Interface */
/**************************/
unsigned char *mac_hmac_hash(
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
unsigned char *mac_hmac_blake224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_blake256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_blake384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_blake512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*************************/
/* HMAC BLAKE2 Interface */
/*************************/
unsigned char *mac_hmac_blake2b(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_blake2s(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/***********************/
/* HMAC GOST Interface */
/***********************/
unsigned char *mac_hmac_gost(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/************************/
/* HMAC HAVAL Interface */
/************************/
unsigned char *mac_hmac_haval256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_haval224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_haval192(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_haval160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_haval128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*********************/
/* HMAC MD Interface */
/*********************/
unsigned char *mac_hmac_md2(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_md4(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_md5(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*************************/
/* HMAC RIPEMD Interface */
/*************************/
unsigned char *mac_hmac_ripemd128(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_ripemd160(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_ripemd256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_ripemd320(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/**********************/
/* HMAC SHA Interface */
/**********************/
unsigned char *mac_hmac_sha1(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_sha224(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_sha256(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_sha384(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_sha512(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/*******************/
/* TIGER Interface */
/*******************/
unsigned char *mac_hmac_tiger(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
unsigned char *mac_hmac_tiger2(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/***********************/
/* WHIRLPOOL Interface */
/***********************/
unsigned char *mac_hmac_whirlpool(
	unsigned char *out,
	const unsigned char *key,
	size_t key_len,
	const unsigned char *msg,
	size_t msg_len);
/**********************/
/* Poly1305 Interface */
/**********************/
unsigned char *mac_poly1305_hash(
	unsigned char *out,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len);
int mac_poly1305_verify(
	const unsigned char *mac,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len);
/********************/
/* Common Interface */
/********************/
void mac_destroy(unsigned char *digest);

#endif

