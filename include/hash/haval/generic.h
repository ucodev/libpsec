/*
 * @file generic.h
 * @brief PSEC Library
 *        HASH [HAVAL] generic interface header
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

#ifndef LIBPSEC_GENERIC_HAVAL_H
#define LIBPSEC_GENERIC_HAVAL_H

#include <stdio.h>

/* Definitions */
#define HAVAL256_HASH_DIGEST_SIZE		32
#define HAVAL256_HASH_BLOCK_SIZE		128
#define HAVAL224_HASH_DIGEST_SIZE		28
#define HAVAL224_HASH_BLOCK_SIZE		128
#define HAVAL192_HASH_DIGEST_SIZE		24
#define HAVAL192_HASH_BLOCK_SIZE		128
#define HAVAL160_HASH_DIGEST_SIZE		20
#define HAVAL160_HASH_BLOCK_SIZE		128
#define HAVAL128_HASH_DIGEST_SIZE		16
#define HAVAL128_HASH_BLOCK_SIZE		128


/* Prototypes */

/* HAVAL-256 Generic Interface */
unsigned char *haval256_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *haval256_file(unsigned char *out, FILE *fp);
/* HAVAL-224 Generic Interface */
unsigned char *haval224_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *haval224_file(unsigned char *out, FILE *fp);
/* HAVAL-192 Generic Interface */
unsigned char *haval192_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *haval192_file(unsigned char *out, FILE *fp);
/* HAVAL-160 Generic Interface */
unsigned char *haval160_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *haval160_file(unsigned char *out, FILE *fp);
/* HAVAL-128 Generic Interface */
unsigned char *haval128_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *haval128_file(unsigned char *out, FILE *fp);

#endif

