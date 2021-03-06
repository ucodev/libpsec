/*
 * @file generic.h
 * @brief PSEC Library
 *        AES Encryption/Decryption interface header
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

#ifndef LIBPSEC_CRYPT_AES_GENERIC_H
#define LIBPSEC_CRYPT_AES_GENERIC_H

#include <stdio.h>

/* Prototypes */
unsigned char *aes256cbc_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes256cbc_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes256ecb_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes256ecb_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes192cbc_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes192cbc_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes192ecb_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes192ecb_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes128cbc_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes128cbc_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes128ecb_encrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);
unsigned char *aes128ecb_decrypt(
        unsigned char *out,
	size_t *out_len,
        const unsigned char *in,
        size_t in_len,
        const unsigned char *nonce,
        const unsigned char *key);

#endif

