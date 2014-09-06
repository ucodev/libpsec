/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [RIPEMD] low level interface
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

#include "hash/ripemd/low.h"
#include "hash/ripemd/rmd256.h"

#include "tc.h"

/* RIPEMD-128 Low Level Interface */
int ripemd256_low_init(uint32_t *context) {
	RIPEMD256_init(context);

	return 0;
}

int ripemd256_low_update(uint32_t *context, const unsigned char *in, size_t in_len) {
	int i = 0;
	uint32_t X[16];

	for (i = 0; in_len >= sizeof(X); i += sizeof(X), in_len -= sizeof(X)) {
		tc_memcpy(X, in + i, sizeof(X));
		RIPEMD256_compress(context, X);
	}

	RIPEMD256_finish(context, in + i, in_len, 0);

	return 0;
}

int ripemd256_low_final(uint32_t *context, unsigned char *out) {
	int i = 0;

	for (i = 0; i < 32; i += 4) {
		out[i]     = context[i >> 2];
		out[i + 1] = context[i >> 2] >> 8;
		out[i + 2] = context[i >> 2] >> 16;
		out[i + 3] = context[i >> 2] >> 24;
	}

	return 0;
}

