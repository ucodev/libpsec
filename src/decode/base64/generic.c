/*
 * @file generic.c
 * @brief PSEC Library
 *        Base64 Decoding interface 
 *
 * Date: 11-08-2014
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "decode/base64/generic.h"

static int _get_index(uint8_t code) {
	int i = 0;

	if (code == (unsigned char) '=')
		return 0;

	for (i = 0; i < sizeof(_base64_index) - 1; i ++) {
		if (code == _base64_index[i])
			break;
	}

	return i;
}

size_t base64_decode_size(size_t in_len) {
	unsigned int align = 4 - (in_len % 4);
	float fval = ((float) in_len + ((align == 4) ? 0 : align)) * 0.75;
	size_t ret = (unsigned int) fval;

	ret += ((fval - ((float) ret)) > 0) ? 1 : 0;

	return ret;
}

unsigned char *base64_decode(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	int i = 0, j = 0, left = 0, out_alloc = 0;
	uint8_t align[4] = { '=', '=', '=', '=' };
	const uint8_t *context = (uint8_t *) in;

	if (!out) {
		if (!(out = malloc(base64_decode_size(in_len))))
			return NULL;

		out_alloc = 1;
	}

	for (i = 0, j = 0; (i + 4) <= in_len; i += 4, j += 3) {
		out[j] = (_get_index(context[i]) << 2) | (_get_index(context[i + 1]) >> 4);
		out[j + 1] = ((_get_index(context[i + 1]) & 0x0f) << 4) | (_get_index(context[i + 2]) >> 2);
		out[j + 2] = ((_get_index(context[i + 2]) & 0x03) << 6) | _get_index(context[i + 3]);
	}

	if (!(left = in_len - i)) {
		*out_len = j;
		return out;
	}

	memcpy(align, &context[i], left);
	context = align;

	if (!base64_decode(&out[j], out_len, (const unsigned char *) context, 4)) {
		if (out_alloc) free(out);
		return NULL;
	}

	*out_len += j;

	return out;
}

