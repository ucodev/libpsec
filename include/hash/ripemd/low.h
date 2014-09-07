/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [RIPEMD] low level interface header
 *
 * Date: 07-09-2014
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

#ifndef LIBPSEC_RIPEMD_LOW_H
#define LIBPSEC_RIPEMD_LOW_H

#include <stdio.h>
#include <stdint.h>

/* Context types */
typedef struct ripemd128_struct {
	uint32_t digest[4];
	unsigned char block[64];
	size_t blen;
	size_t mlen;
} ripemd128_state;

typedef struct ripemd160_struct {
	uint32_t digest[5];
	unsigned char block[64];
	size_t blen;
	size_t mlen;
} ripemd160_state;

typedef struct ripemd256_struct {
	uint32_t digest[8];
	unsigned char block[64];
	size_t blen;
	size_t mlen;
} ripemd256_state;

typedef struct ripemd320_struct {
	uint32_t digest[10];
	unsigned char block[64];
	size_t blen;
	size_t mlen;
} ripemd320_state;

/* RIPEMD-128 Low Level Interface */
int ripemd128_low_init(ripemd128_state *context);
int ripemd128_low_update(ripemd128_state *context, const unsigned char *in, size_t in_len);
int ripemd128_low_final(ripemd128_state *context, unsigned char *out);

/* RIPEMD-160 Low Level Interface */
int ripemd160_low_init(ripemd160_state *context);
int ripemd160_low_update(ripemd160_state *context, const unsigned char *in, size_t in_len);
int ripemd160_low_final(ripemd160_state *context, unsigned char *out);

/* RIPEMD-256 Low Level Interface */
int ripemd256_low_init(ripemd256_state *context);
int ripemd256_low_update(ripemd256_state *context, const unsigned char *in, size_t in_len);
int ripemd256_low_final(ripemd256_state *context, unsigned char *out);

/* RIPEMD-320 Low Level Interface */
int ripemd320_low_init(ripemd320_state *context);
int ripemd320_low_update(ripemd320_state *context, const unsigned char *in, size_t in_len);
int ripemd320_low_final(ripemd320_state *context, unsigned char *out);

#endif

