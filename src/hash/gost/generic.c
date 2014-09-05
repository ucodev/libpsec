/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [GOST] generic interface
 *
 * Date: 05-09-2014
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

#include "hash/gost/generic.h"
#include "hash/gost/gosthash.h"

/* GOST Generic Interface */
unsigned char *gost_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	GostHashCtx gost;
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(GOST_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	gosthash_reset(&gost);
	gosthash_update(&gost, in, in_len);
	gosthash_final(&gost, digest);

	return digest;
}

unsigned char *gost_file(unsigned char *out, FILE *fp) {
	GostHashCtx gost;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	gosthash_reset(&gost);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		gosthash_update(&gost, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(GOST_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	gosthash_final(&gost, digest);

	return digest;
}


