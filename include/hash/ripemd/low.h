/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [RIPEMD] low level interface header
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

#ifndef LIBPSEC_RIPEMD_LOW_H
#define LIBPSEC_RIPEMD_LOW_H

#include <stdio.h>
#include <stdint.h>

/* RIPEMD-128 Low Level Interface */
int ripemd128_low_init(uint32_t *context);
int ripemd128_low_update(uint32_t *context, const unsigned char *in, size_t in_len);
int ripemd128_low_final(uint32_t *context, unsigned char *out);

/* RIPEMD-160 Low Level Interface */
int ripemd160_low_init(uint32_t *context);
int ripemd160_low_update(uint32_t *context, const unsigned char *in, size_t in_len);
int ripemd160_low_final(uint32_t *context, unsigned char *out);

/* RIPEMD-256 Low Level Interface */
int ripemd256_low_init(uint32_t *context);
int ripemd256_low_update(uint32_t *context, const unsigned char *in, size_t in_len);
int ripemd256_low_final(uint32_t *context, unsigned char *out);

/* RIPEMD-320 Low Level Interface */
int ripemd320_low_init(uint32_t *context);
int ripemd320_low_update(uint32_t *context, const unsigned char *in, size_t in_len);
int ripemd320_low_final(uint32_t *context, unsigned char *out);

#endif

