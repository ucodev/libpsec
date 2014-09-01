/*
 * @file crypt.h
 * @brief PSEC Library
 *        Encryption/Decryption interface header
 *
 * Date: 02-09-2014
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

#ifndef LIBPSEC_CRYPT_H
#define LIBPSEC_CRYPT_H

#include <stdio.h>

/* Prototypes */
/*****************/
/* AES Interface */
/*****************/
#define CRYPT_KEY_SIZE_AES256			32
#define CRYPT_NONCE_SIZE_AES256			16
#define CRYPT_EXTRA_SIZE_AES256			16 + 16
unsigned char *crypt_encrypt_aes256cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes256cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_encrypt_aes256ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes256ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
#define CRYPT_KEY_SIZE_AES192			24
#define CRYPT_NONCE_SIZE_AES192			16
#define CRYPT_EXTRA_SIZE_AES192			16 + 16
unsigned char *crypt_encrypt_aes192cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes192cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_encrypt_aes192ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes192ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
#define CRYPT_KEY_SIZE_AES128			16
#define CRYPT_NONCE_SIZE_AES128			16
#define CRYPT_EXTRA_SIZE_AES128			16 + 16
unsigned char *crypt_encrypt_aes128cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes128cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_encrypt_aes128ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_aes128ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
/********************/
/* ChaCha Interface */
/********************/
#define CRYPT_KEY_SIZE_CHACHA20			32
#define CRYPT_NONCE_SIZE_CHACHA20		8
#define CRYPT_EXTRA_SIZE_CHACHA20POLY1305	16
unsigned char *crypt_encrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_encrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
/*****************/
/* OTP Interface */
/*****************/
unsigned char *crypt_encrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
/**********************/
/* Xsalsa20 Interface */
/**********************/
#define CRYPT_KEY_SIZE_XSALSA20			32
#define CRYPT_NONCE_SIZE_XSALSA20		24
#define CRYPT_EXTRA_SIZE_XSALSA20POLY1305	16
unsigned char *crypt_encrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_encrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
unsigned char *crypt_decrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key);
/********************/
/* Common Interface */
/********************/
void crypt_destroy(unsigned char *crypt);

#endif

