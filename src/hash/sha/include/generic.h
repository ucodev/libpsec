/*
 * @file generic.h
 * @brief PSEC Library
 *        HASH [SHA] generic interface header
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

#ifndef LIBPSEC_GENERIC_SHA_H
#define LIBPSEC_GENERIC_SHA_H

/* Definitions */
#define SHA1_HASH_DIGEST_SIZE		20
#define SHA224_HASH_DIGEST_SIZE		28
#define SHA256_DIGEST_SIZE		32
#define SHA384_HASH_DIGEST_SIZE		48
#define SHA512_HASH_DIGEST_SIZE		64


/* Prototypes */

/* SHA1 Generic Interface */
char *sha1_generic_create(const char *in, size_t len);
void sha1_generic_destroy(char *digest);
/* SHA224 Generic Interface */
char *sha224_generic_create(const char *in, size_t len);
void sha224_generic_destroy(char *digest);
/* SHA256 Generic Interface */
char *sha256_generic_create(const char *in, size_t len);
void sha256_generic_destroy(char *digest);
/* SHA384 Generic Interface */
char *sha384_generic_create(const char *in, size_t len);
void sha384_generic_destroy(char *digest);
/* SHA512 Generic Interface */
char *sha512_generic_create(const char *in, size_t len);
void sha512_generic_destroy(char *digest);

#endif

