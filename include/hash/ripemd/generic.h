/*
 * @file generic.h
 * @brief PSEC Library
 *        HASH [RIPEMD] generic interface header
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

#ifndef LIBPSEC_GENERIC_RIPEMD_H
#define LIBPSEC_GENERIC_RIPEMD_H

#include <stdio.h>

/* Definitions */
#define RIPEMD128_HASH_DIGEST_SIZE		16
#define RIPEMD128_HASH_BLOCK_SIZE		64
#define RIPEMD160_HASH_DIGEST_SIZE		20
#define RIPEMD160_HASH_BLOCK_SIZE		64
#define RIPEMD256_HASH_DIGEST_SIZE		32
#define RIPEMD256_HASH_BLOCK_SIZE		64
#define RIPEMD320_HASH_DIGEST_SIZE		40
#define RIPEMD320_HASH_BLOCK_SIZE		64


/* Prototypes */

/* RIPEMD-128 Generic Interface */
unsigned char *ripemd128_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *ripemd128_file(unsigned char *out, FILE *fp);
/* RIPEMD-160 Generic Interface */
unsigned char *ripemd160_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *ripemd160_file(unsigned char *out, FILE *fp);
/* RIPEMD-160 Generic Interface */
unsigned char *ripemd256_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *ripemd256_file(unsigned char *out, FILE *fp);
/* RIPEMD-320 Generic Interface */
unsigned char *ripemd320_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *ripemd320_file(unsigned char *out, FILE *fp);



#endif

