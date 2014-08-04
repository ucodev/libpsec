/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [MD4] generic interface
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

#include "hash/md4/generic.h"
#include "hash/md4/global.h"
#include "hash/md4/md4.h"

/* MD4 Generic Interface */
char *md4_buffer(char *out, const char *in, size_t len) {
	MD4_CTX md4;
	char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(MD4_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD4Init(&md4);
	MD4Update(&md4, in, len);
	MD4Final(digest, &md4);

	return digest;
}

char *md4_file(char *out, FILE *fp) {
	MD4_CTX md4;
	size_t ret = 0;
	int errsv = 0;
	char buf[8192], *digest = NULL;

	MD4Init(&md4);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		MD4Update(&md4, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(MD4_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD4Final(digest, &md4);

	return digest;
}


