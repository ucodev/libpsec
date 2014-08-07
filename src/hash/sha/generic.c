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

#include "hash/sha/generic.h"
#include "hash/sha/sha.h"

/* SHA1 Generic Interface */
unsigned char *sha1_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	SHA1Context sha1;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA1HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA1Reset(&sha1);
	SHA1Input(&sha1, (const uint8_t *) in, in_len);

	if (SHA1Result(&sha1, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (unsigned char *) digest;
}

unsigned char *sha1_file(unsigned char *out, FILE *fp) {
	SHA1Context sha1;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192];
	uint8_t *digest = NULL;

	SHA1Reset(&sha1);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		SHA1Input(&sha1, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(SHA1HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA1Result(&sha1, digest);

	return (unsigned char *) digest;
}

/* SHA224 Generic Interface */
unsigned char *sha224_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	SHA224Context sha224;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA224HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA224Reset(&sha224);
	SHA224Input(&sha224, (const uint8_t *) in, in_len);

	if (SHA224Result(&sha224, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (unsigned char *) digest;
}

unsigned char *sha224_file(unsigned char *out, FILE *fp) {
	SHA224Context sha224;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192];
	uint8_t *digest = NULL;

	SHA224Reset(&sha224);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		SHA224Input(&sha224, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(SHA224HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA224Result(&sha224, digest);

	return (unsigned char *) digest;
}

/* SHA256 Generic Interface */
unsigned char *sha256_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	SHA256Context sha256;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA256HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA256Reset(&sha256);
	SHA256Input(&sha256, (const uint8_t *) in, in_len);

	if (SHA256Result(&sha256, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (unsigned char *) digest;
}

unsigned char *sha256_file(unsigned char *out, FILE *fp) {
	SHA256Context sha256;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192];
	uint8_t *digest = NULL;

	SHA256Reset(&sha256);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		SHA256Input(&sha256, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(SHA256HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA256Result(&sha256, digest);

	return (unsigned char *) digest;
}

/* SHA384 Generic Interface */
unsigned char *sha384_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	SHA384Context sha384;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA384HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA384Reset(&sha384);
	SHA384Input(&sha384, (const uint8_t *) in, in_len);

	if (SHA384Result(&sha384, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (unsigned char *) digest;
}

unsigned char *sha384_file(unsigned char *out, FILE *fp) {
	SHA384Context sha384;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192];
	uint8_t *digest = NULL;

	SHA384Reset(&sha384);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		SHA384Input(&sha384, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(SHA384HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA384Result(&sha384, digest);

	return (unsigned char *) digest;
}

/* SHA512 Generic Interface */
unsigned char *sha512_buffer(unsigned char *out, const unsigned char *in, size_t in_len) {
	SHA512Context sha512;
	uint8_t *digest = NULL;

	if (!out) {
		if (!(digest = malloc(SHA512HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA512Reset(&sha512);
	SHA512Input(&sha512, (const uint8_t *) in, in_len);

	if (SHA512Result(&sha512, digest)) {
		free(digest);
		errno = EINVAL;
		return NULL;
	}

	return (unsigned char *) digest;
}

unsigned char *sha512_file(unsigned char *out, FILE *fp) {
	SHA512Context sha512;
	size_t ret = 0;
	int errsv = 0;
	unsigned char buf[8192];
	uint8_t *digest = NULL;

	SHA512Reset(&sha512);

	for (;;) {
		ret = fread(buf, 1, 8192, fp);
		errsv = errno;

		if ((ret != 8192) && ferror(fp)) {
			errno = errsv;
			return NULL;
		}

		SHA512Input(&sha512, (const uint8_t *) buf, ret);

		if (feof(fp))
			break;
	}

	if (!out) {
		if (!(digest = malloc(SHA512HashSize)))
			return NULL;
	} else {
		digest = (uint8_t *) out;
	}

	SHA512Result(&sha512, digest);

	return (unsigned char *) digest;
}

