/*
 * @file generic.c
 * @brief PSEC Library
 *        ChaChaXX+Poly1305 Secret box interface
 *
 * Date: 21-08-2014
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

/*
 * Based on Xsalsa20 secretbox developed by D. J. Bernstein (NaCl library: http://nacl.cr.yp.to/)
 */

#include "crypt/chacha/crypto.h"
#include "mac/poly1305/crypto.h"

int crypto_secretbox_chacha(
	unsigned char *c,
	const unsigned char *m,
	unsigned long long mlen,
	const unsigned char *n,
	const unsigned char *k,
	size_t rounds)
{
	int i = 0;
	unsigned char subkey[64];

	if (mlen < 32)
		return -1;

	crypto_core_chacha(subkey, k, n, 0, 256, rounds);
	crypto_core_chacha_xor(c, m, mlen, n, k, 1, 256, rounds);
	crypto_onetimeauth_poly1305(c + 16, c + 32, mlen - 32, subkey);

	for (i = 0; i < 16; ++i)
		c[i] = 0;

	return 0;
}

int crypto_secretbox_chacha_open(
	unsigned char *m,
	const unsigned char *c,
	unsigned long long clen,
	const unsigned char *n,
	const unsigned char *k,
	size_t rounds)
{
	int i;
	unsigned char subkey[64];

	if (clen < 32)
		return -1;

	crypto_core_chacha(subkey, k, n, 0, 256, rounds);

	if (crypto_onetimeauth_poly1305_verify(c + 16, c + 32, clen - 32, subkey))
		return -1;

	crypto_core_chacha_xor(m, c, clen, n, k, 1, 256, rounds);

	for (i = 0; i < 32; ++i)
		m[i] = 0;

	return 0;
}

