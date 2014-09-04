/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [MD2] generic interface
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

#include "hash/md2/generic.h"
#include "hash/md2/global.h"
#include "hash/md2/md2.h"

/* MD2 Generic Interface */
unsigned char *md2_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	MD2_CTX md2;
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(MD2_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD2Init(&md2);
	MD2Update(&md2, in, in_len);
	MD2Final(digest, &md2);

	return digest;
}

unsigned char *md2_file(unsigned char *out, FILE *fp) {
	MD2_CTX md2;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	MD2Init(&md2);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		MD2Update(&md2, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(MD2_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD2Final(digest, &md2);

	return digest;
}

