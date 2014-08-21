/*
 * @file generic.c
 * @brief PSEC Library
 *        Poly1305 Message Authentication Code interface 
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include "mac/poly1305/crypto.h"

unsigned char *poly1305_auth(
	unsigned char *out,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len)
{
	int errsv = 0, out_alloc = 0;

	if (!out) {
		if (!(out = malloc(16)))
			return NULL;

		out_alloc = 1;
	}

	if (crypto_onetimeauth_poly1305(out, msg, msg_len, key) < 0) {
		errsv = errno;
		if (out_alloc) free(out);
		errno = errsv;
		return NULL;
	}

	return out;
}

int poly1305_verify(
	const unsigned char *mac,
	const unsigned char *key,
	const unsigned char *msg,
	size_t msg_len)
{
	return crypto_onetimeauth_poly1305_verify(mac, msg, msg_len, key);
}

