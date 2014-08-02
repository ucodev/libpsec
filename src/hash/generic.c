/*
 * @file generic.c
 * @brief PSEC Library
 *        HASH interface 
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

#include "sha/include/generic.h"
#include "md5/include/generic.h"

/* SHA Interface */
char *hash_sha1_create(char *out, const char *in, size_t len) {
	return sha1_generic_create(out, in, len);
}

char *hash_sha224_create(char *out, const char *in, size_t len) {
	return sha224_generic_create(out, in, len);
}

char *hash_sha256_create(char *out, const char *in, size_t len) {
	return sha256_generic_create(out, in, len);
}

char *hash_sha384_create(char *out, const char *in, size_t len) {
	return sha384_generic_create(out, in, len);
}

char *hash_sha512_create(char *out, const char *in, size_t len) {
	return sha512_generic_create(out, in, len);
}

void hash_sha1_destroy(char *digest) {
	sha1_generic_destroy(digest);
}

void hash_sha224_destroy(char *digest) {
	sha224_generic_destroy(digest);
}

void hash_sha256_destroy(char *digest) {
	sha256_generic_destroy(digest);
}

void hash_sha384_destroy(char *digest) {
	sha384_generic_destroy(digest);
}

void hash_sha512_destroy(char *digest) {
	sha512_generic_destroy(digest);
}


/* MD Interface */
char *hash_md5_create(char *out, const char *in, size_t len) {
	return md5_generic_create(out, in, len);
}

void hash_md5_destroy(char *digest) {
	md5_generic_destroy(digest);
}


