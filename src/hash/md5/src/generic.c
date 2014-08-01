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

#include <stdlib.h>

#include "generic.h"
#include "global.h"
#include "md5.h"

/* MD5 Generic Interface */
char *md5_generic_create(const char *in, size_t len) {
	MD5_CTX md5;
	char *digest = NULL;

	if (!(digest = malloc(MD5_HASH_DIGEST_SIZE)))
		return NULL;

	MD5Init(&md5);
	MD5Update(&md5, in, len);
	MD5Final(digest, &md5);

	return digest;
}

void md5_generic_destroy(char *digest) {
	free(digest);
}

