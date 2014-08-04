/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [Blake2] generic interface
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

#include "hash/blake2/generic.h"
#include "hash/blake2/blake2.h"

/* Blake2b Generic Interface */
char *blake2b_buffer(char *out, const char *in, size_t len) {
	blake2b_state blake2b;
	char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(BLAKE2B_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	blake2b_init(&blake2b, BLAKE2B_OUTBYTES);
	blake2b_update(&blake2b, (const uint8_t *) in, len);
	blake2b_final(&blake2b, (uint8_t *) digest, BLAKE2B_OUTBYTES);

	return digest;
}

char *blake2b_file(char *out, FILE *fp) {
	blake2b_state blake2b;
	size_t ret = 0;
	int errsv = 0;
	char buf[8192], *digest = NULL;

	blake2b_init(&blake2b, BLAKE2B_OUTBYTES);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake2b_update(&blake2b, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(BLAKE2B_OUTBYTES)))
			return NULL;
	} else {
		digest = out;
	}

	blake2b_final(&blake2b, (uint8_t *) digest, BLAKE2B_OUTBYTES);

	return digest;
}

/* Blake2s Generic Interface */
char *blake2s_buffer(char *out, const char *in, size_t len) {
	blake2s_state blake2s;
	char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(BLAKE2S_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	blake2s_init(&blake2s, BLAKE2S_OUTBYTES);
	blake2s_update(&blake2s, (const uint8_t *) in, len);
	blake2s_final(&blake2s, (uint8_t *) digest, BLAKE2S_OUTBYTES);

	return digest;
}

char *blake2s_file(char *out, FILE *fp) {
	blake2s_state blake2s;
	size_t ret = 0;
	int errsv = 0;
	char buf[8192], *digest = NULL;

	blake2s_init(&blake2s, BLAKE2S_OUTBYTES);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		blake2s_update(&blake2s, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(BLAKE2S_OUTBYTES)))
			return NULL;
	} else {
		digest = out;
	}

	blake2s_final(&blake2s, (uint8_t *) digest, BLAKE2S_OUTBYTES);

	return digest;
}


