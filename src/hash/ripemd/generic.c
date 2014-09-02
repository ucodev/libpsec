/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [RIPEMD] generic interface
 *
 * Date: 02-08-2014
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
#include <errno.h>

#include "hash/ripemd/generic.h"
#include "hash/ripemd/low.h"

/* RIPEMD-128 Generic Interface */
unsigned char *ripemd128_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	uint32_t context[4];
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(RIPEMD128_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	ripemd128_low_init(context);
	ripemd128_low_update(context, in, in_len);
	ripemd128_low_final(context, digest);

	return digest;
}

unsigned char *ripemd128_file(unsigned char *out, FILE *fp) {
	uint32_t context[4];
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	ripemd128_low_init(context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		ripemd128_low_update(context, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(RIPEMD128_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	ripemd128_low_final(context, digest);

	return digest;
}

/* RIPEMD-160 Generic Interface */
unsigned char *ripemd160_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	uint32_t context[5];
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(RIPEMD160_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	ripemd160_low_init(context);
	ripemd160_low_update(context, in, in_len);
	ripemd160_low_final(context, digest);

	return digest;
}

unsigned char *ripemd160_file(unsigned char *out, FILE *fp) {
	uint32_t context[5];
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	ripemd160_low_init(context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		ripemd160_low_update(context, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(RIPEMD160_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	ripemd160_low_final(context, digest);

	return digest;
}

