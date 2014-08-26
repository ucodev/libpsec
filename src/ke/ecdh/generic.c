/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [ECDH] interface 
 *
 * Date: 26-08-2014
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
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "ke/ecdh/curve25519.h"
#include "generate.h"

/* Functions */

unsigned char *ecdh_init_private_key(unsigned char *priv, size_t priv_size) {
	/* Validate key length */
	if (priv_size != 32) {
		errno = EINVAL;
		return NULL;
	}

	/* Generate private key */
	return generate_bytes_random(priv, priv_size);
}

unsigned char *ecdh_compute_public_key(
	unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	int errsv = 0, pub_alloc = 0;
	unsigned char basepoint[32];

	/* Validate key length */
	if ((pub_size != 32) || (priv_size != 32)) {
		errno = EINVAL;
		return NULL;
	}

	/* Initialize basepoint */
	memset(basepoint, 0, sizeof(basepoint));
	basepoint[0] = 9;

	/* Allocate memory for public key if required */
	if (!pub) {
		if (!(pub = malloc(pub_size)))
			return NULL;

		pub_alloc = 1;
	}

	/* Scalar multiplication */
	if (crypto_scalarmult_curve25519_ref(pub, priv, basepoint) < 0) {
		errsv = errno;
		if (pub_alloc) free(pub);
		errno = errsv;
		return NULL;
	}

	/* All good */
	return pub;
}

unsigned char *ecdh_compute_shared_key(
	unsigned char *shared,
	const unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	int errsv = 0, shared_alloc = 0;

	/* Validate key length */
	if ((pub_size != 32) || (priv_size != 32)) {
		errno = EINVAL;
		return NULL;
	}

	/* Allocate memory for public key if required */
	if (!shared) {
		if (!(shared = malloc(pub_size)))
			return NULL;

		shared_alloc = 1;
	}

	/* Scalar multiplication */
	if (crypto_scalarmult_curve25519_ref(shared, priv, pub) < 0) {
		errsv = errno;
		if (shared_alloc) free(shared);
		errno = errsv;
		return NULL;
	}

	/* All good */
	return shared;
}

