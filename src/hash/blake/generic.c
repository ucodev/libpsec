/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [BLAKE] generic interface
 *
 * Date: 04-09-2014
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

#include "hash/blake/generic.h"
#include "hash/blake/blake-proto.h"

/* BLAKE-224 Generic Interface */
unsigned char *blake224_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	state224 context;
	unsigned char *digest = NULL;

	blake224_init(&context);

	if (!out) {
		if (!(digest = malloc(28)))
			return NULL;
	} else {
		digest = out;
	}

	blake224_update(&context, (const uint8_t *) in, in_len);
	blake224_final(&context, (uint8_t *) digest);

	return digest;
}

unsigned char *blake224_file(unsigned char *out, FILE *fp) {
	state224 context;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	blake224_init(&context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake224_update(&context, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(28)))
			return NULL;
	} else {
		digest = out;
	}

	blake224_final(&context, (uint8_t *) digest);

	return digest;
}

/* BLAKE-256 Generic Interface */
unsigned char *blake256_buffer(
	unsigned char *out,
	const unsigned char *in,
	size_t in_len)
{
	state256 context;
	unsigned char *digest = NULL;

	blake256_init(&context);

	if (!out) {
		if (!(digest = malloc(32)))
			return NULL;
	} else {
		digest = out;
	}

	blake256_update(&context, (const uint8_t *) in, in_len);
	blake256_final(&context, (uint8_t *) digest);

	return digest;
}

unsigned char *blake256_file(unsigned char *out, FILE *fp) {
	state256 context;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	blake256_init(&context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake256_update(&context, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(32)))
			return NULL;
	} else {
		digest = out;
	}

	blake256_final(&context, (uint8_t *) digest);

	return digest;
}

/* BLAKE-384 Generic Interface */
unsigned char *blake384_buffer(
	unsigned char *out,
	const unsigned char *in,
	size_t in_len)
{
	state384 context;
	unsigned char *digest = NULL;

	blake384_init(&context);

	if (!out) {
		if (!(digest = malloc(48)))
			return NULL;
	} else {
		digest = out;
	}

	blake384_update(&context, (const uint8_t *) in, in_len);
	blake384_final(&context, (uint8_t *) digest);

	return digest;
}

unsigned char *blake384_file(unsigned char *out, FILE *fp) {
	state384 context;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	blake384_init(&context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake384_update(&context, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(48)))
			return NULL;
	} else {
		digest = out;
	}

	blake384_final(&context, (uint8_t *) digest);

	return digest;
}

/* BLAKE-512 Generic Interface */
unsigned char *blake512_buffer(
	unsigned char *out,
	const unsigned char *in,
	size_t in_len)
{
	state512 context;
	unsigned char *digest = NULL;

	blake512_init(&context);

	if (!out) {
		if (!(digest = malloc(64)))
			return NULL;
	} else {
		digest = out;
	}

	blake512_update(&context, (const uint8_t *) in, in_len);
	blake512_final(&context, (uint8_t *) digest);

	return digest;
}

unsigned char *blake512_file(unsigned char *out, FILE *fp) {
	state512 context;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	blake512_init(&context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake512_update(&context, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(64)))
			return NULL;
	} else {
		digest = out;
	}

	blake512_final(&context, (uint8_t *) digest);

	return digest;
}

