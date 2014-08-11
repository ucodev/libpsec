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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "encode/base64/generic.h"

unsigned char *base64_encode(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	int i = 0, j = 0, left = 0, out_alloc = 0;
	uint8_t align[3] = { 0, 0, 0 };
	const uint8_t *context = (uint8_t *) in;

	if (!out) {
		if (!(out = malloc((in_len + 3) * 1.4)))
			return NULL;

		out_alloc = 1;
	}

	for (i = 0, j = 0; (i + 3) <= in_len; i += 3, j += 4) {
		if (*out_len && ((j + 4) > *out_len)) {
			if (out_alloc) free(out);
			return NULL;
		}

		out[j]     = _base64_index[context[i] >> 2];
		out[j + 1] = _base64_index[((context[i] & 0x03) << 4) | (context[i + 1] >> 4)];
		out[j + 2] = _base64_index[((context[i + 1] & 0x0f) << 2) | (context[i + 2] >> 6)];
		out[j + 3] = _base64_index[context[i + 2] & 0x3f];
	}

	if (!(left = in_len - i)) {
		*out_len = j;
		out[j] = 0;
		return out;
	}

	if (*out_len && ((j + 5) > *out_len)) {
		if (out_alloc) free(out);
		return NULL;
	}

	memcpy(align, &in[i], left);
	context = align;
	out[j + 4] = i = 0;

	switch (left) {
		case 2: out[j + 2] = _base64_index[((context[i + 1] & 0x0f) << 2) | (context[i + 2] >> 6)];
		case 1: out[j] = _base64_index[context[i] >> 2];
			out[j + 1] = _base64_index[((context[i] & 0x03) << 4) | (context[i + 1] >> 4)];
			out[j + 3] = '=';
			if (left == 1) out[j + 2] = '=';
	}

	*out_len = j + 4 + 1;

	return out;
}

