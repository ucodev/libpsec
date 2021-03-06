/*
 * @file generic.c
 * @brief PSEC Library
 *        Base64 Encoding interface 
 *
 * Date: 11-08-2014
 *
 * Copyright 2014 Pedro A. Hortas (pah@ucodev.org)
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this context for additional information
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
#include <stdlib.h>

#include "encode/base16/generic.h"

static uint8_t _nibble_to_hex_char(uint8_t nibble) {
	if (nibble > 15)
		return (uint8_t) 0;

	return (uint8_t) nibble + (nibble < 10 ? 48 : 87);
}

size_t base16_encode_size(size_t in_len) {
	return (in_len * 2) + 1;
}

unsigned char *base16_encode(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	int i = 0;
	const uint8_t *work = (const uint8_t *) in;

	if (!out) {
		if (!(out = malloc(base16_encode_size(in_len))))
			return NULL;
	}

	for (i = 0; i < in_len; i ++) {
		out[(i * 2)] = _nibble_to_hex_char((work[i] & 0xf0) >> 4);
		out[(i * 2) + 1] = _nibble_to_hex_char(work[i] & 0x0f);
	}

	*out_len = (i * 2) + 1;
	out[*out_len - 1] = 0;

	return out;
}

