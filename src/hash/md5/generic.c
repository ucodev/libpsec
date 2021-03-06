/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [MD5] generic interface
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

#include "hash/md5/generic.h"
#include "hash/md5/global.h"
#include "hash/md5/md5.h"

/* MD5 Generic Interface */
unsigned char *md5_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	MD5_CTX md5;
	unsigned char *digest = NULL;

	if (!out) {
		if (!(digest = malloc(MD5_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD5Init(&md5);
	MD5Update(&md5, in, in_len);
	MD5Final(digest, &md5);

	return digest;
}

unsigned char *md5_file(unsigned char *out, FILE *fp) {
	MD5_CTX md5;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192], *digest = NULL;

	MD5Init(&md5);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		MD5Update(&md5, buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(MD5_HASH_DIGEST_SIZE)))
			return NULL;
	} else {
		digest = out;
	}

	MD5Final(digest, &md5);

	return digest;
}

