/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [WHIRLPOOL] generic interface
 *
 * Date: 03-08-2014
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

#include "hash/whirlpool/generic.h"
#include "hash/whirlpool/nessie.h"

/* WHIRLPOOL Generic Interface */
unsigned char *whirlpool_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	struct NESSIEstruct context;
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(WHIRLPOOL_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	NESSIEinit(&context);
	NESSIEadd(in, in_len << 3, &context);
	NESSIEfinalize(&context, digest);

	return digest;
}

unsigned char *whirlpool_file(unsigned char *out, FILE *fp) {
	struct NESSIEstruct context;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	NESSIEinit(&context);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		NESSIEadd(buf, ret << 3, &context);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(WHIRLPOOL_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	NESSIEfinalize(&context, digest);

	return digest;
}

