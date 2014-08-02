/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH [SHA] generic interface
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
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>

#include "generic.h"
#include "sha.h"

/* SHA1 Generic Interface */
char *sha1_generic_create(char *out, const char *in, size_t len) {
	SHA1Context sha1;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA1HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA1Reset(&sha1);
	SHA1Input(&sha1, (const uint8_t *) in, len);

	if (SHA1Result(&sha1, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (char *) digest;
}

void sha1_generic_destroy(char *digest) {
	free(digest);
}

/* SHA224 Generic Interface */
char *sha224_generic_create(char *out, const char *in, size_t len) {
	SHA224Context sha224;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA224HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA224Reset(&sha224);
	SHA224Input(&sha224, (const uint8_t *) in, len);

	if (SHA224Result(&sha224, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (char *) digest;
}

void sha224_generic_destroy(char *digest) {
	free(digest);
}

/* SHA256 Generic Interface */
char *sha256_generic_create(char *out, const char *in, size_t len) {
	SHA256Context sha256;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA256HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA256Reset(&sha256);
	SHA256Input(&sha256, (const uint8_t *) in, len);

	if (SHA256Result(&sha256, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (char *) digest;
}

void sha256_generic_destroy(char *digest) {
	free(digest);
}

/* SHA384 Generic Interface */
char *sha384_generic_create(char *out, const char *in, size_t len) {
	SHA384Context sha384;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA384HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA384Reset(&sha384);
	SHA384Input(&sha384, (const uint8_t *) in, len);

	if (SHA384Result(&sha384, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (char *) digest;
}

void sha384_generic_destroy(char *digest) {
	free(digest);
}

/* SHA512 Generic Interface */
char *sha512_generic_create(char *out, const char *in, size_t len) {
	SHA512Context sha512;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA512HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA512Reset(&sha512);
	SHA512Input(&sha512, (const uint8_t *) in, len);

	if (SHA512Result(&sha512, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (char *) digest;
}

void sha512_generic_destroy(char *digest) {
	free(digest);
}

