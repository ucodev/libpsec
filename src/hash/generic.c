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
#include <stdlib.h>

#include "hash/md4/generic.h"
#include "hash/md5/generic.h"
#include "hash/sha/generic.h"

/* MD Interface */
char *hash_buffer_md4(char *out, const char *in, size_t len) {
	return md4_buffer(out, in, len);
}

char *hash_file_md4(char *out, FILE *fp) {
	return md4_file(out, fp);
}

char *hash_buffer_md5(char *out, const char *in, size_t len) {
	return md5_buffer(out, in, len);
}

char *hash_file_md5(char *out, FILE *fp) {
	return md5_file(out, fp);
}

/* SHA Interface */
char *hash_buffer_sha1(char *out, const char *in, size_t len) {
	return sha1_buffer(out, in, len);
}

char *hash_file_sha1(char *out, FILE *fp) {
	return sha1_file(out, fp);
}

char *hash_buffer_sha224(char *out, const char *in, size_t len) {
	return sha224_buffer(out, in, len);
}

char *hash_file_sha224(char *out, FILE *fp) {
	return sha224_file(out, fp);
}

char *hash_buffer_sha256(char *out, const char *in, size_t len) {
	return sha256_buffer(out, in, len);
}

char *hash_file_sha256(char *out, FILE *fp) {
	return sha256_file(out, fp);
}

char *hash_buffer_sha384(char *out, const char *in, size_t len) {
	return sha384_buffer(out, in, len);
}

char *hash_file_sha384(char *out, FILE *fp) {
	return sha384_file(out, fp);
}

char *hash_buffer_sha512(char *out, const char *in, size_t len) {
	return sha512_buffer(out, in, len);
}

char *hash_file_sha512(char *out, FILE *fp) {
	return sha512_file(out, fp);
}

/* Generic */
void hash_destroy(char *digest) {
	free(digest);
}

