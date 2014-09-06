/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [HAVAL256] generic interface
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "hash/haval/generic.h"
#include "hash/haval/haval.h"

/* HAVAL-256 Generic Interface */
unsigned char *haval256_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	haval_state haval256;
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(HAVAL256_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	haval_start(&haval256);
	haval_set_fptlen(&haval256, 256);
	haval_set_pass(&haval256, 5);
	haval_hash(&haval256, in, in_len);
	haval_end(&haval256, digest);

	return digest;
}

unsigned char *haval256_file(unsigned char *out, FILE *fp) {
	haval_state haval256;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	haval_start(&haval256);
	haval_set_fptlen(&haval256, 256);
	haval_set_pass(&haval256, 5);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		haval_hash(&haval256, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(HAVAL256_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	haval_end(&haval256, digest);

	return digest;
}

