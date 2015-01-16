/*
 * @file generic.c
 * @brief PSEC Library
 *        Encryption/Decryption interface 
 *
 * Date: 16-01-2015
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

#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#include "crypt/aes/generic.h"
#include "crypt/blowfish/generic.h"
#include "crypt/chacha/generic.h"
#include "crypt/salsa/generic.h"
#include "crypt/otp/generic.h"

/* AES-256 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes256cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes256cbc_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes256cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes256cbc_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes256ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes256ecb_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes256ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes256ecb_decrypt(out, out_len, in, in_len, nonce, key);
}

/* AES-192 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes192cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes192cbc_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes192cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes192cbc_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes192ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes192ecb_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes192ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes192ecb_decrypt(out, out_len, in, in_len, nonce, key);
}

/* AES-128 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes128cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes128cbc_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes128cbc(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes128cbc_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_aes128ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes128ecb_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_aes128ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return aes128ecb_decrypt(out, out_len, in, in_len, nonce, key);
}

/* Blowfish-448 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_blowfish448ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return blowfish448ecb_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_blowfish448ecb(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return blowfish448ecb_decrypt(out, out_len, in, in_len, nonce, key);
}

/* ChaCha20 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha20poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

/* ChaCha12 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha12(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha12_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha12(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha12_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha12poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha12poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha12poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha12poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

/* ChaCha8 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha8(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha8_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha8(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha8_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_chacha8poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha8poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_chacha8poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return chacha8poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

/* OTP */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return otp_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_otp(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return otp_decrypt(out, out_len, in, in_len, nonce, key);
}

/* Xsalsa20 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa20(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa20poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa20poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

/* Xsalsa12 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa12(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa12_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa12(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa12_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa12poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa12poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa12poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa12poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

/* Xsalsa8 */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa8(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa8_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa8(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa8_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_encrypt_xsalsa8poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa8poly1305_encrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *crypt_decrypt_xsalsa8poly1305(
	unsigned char *out,
	size_t *out_len,
	const unsigned char *in,
	size_t in_len,
	const unsigned char *nonce,
	const unsigned char *key)
{
	return xsalsa8poly1305_decrypt(out, out_len, in, in_len, nonce, key);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void crypt_destroy(unsigned char *crypt) {
	free(crypt);
}

