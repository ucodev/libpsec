/*
 * @file generic.c
 * @brief PSEC Library
 *        Base16 Encoding interface 
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

#include "decode/base16/generic.h"

static uint8_t _hex_char_to_nibble(uint8_t hex) {
	hex |= 0x20;

	return hex - (hex >= 97 ? 87 : 48);
}

size_t base16_decode_size(size_t in_len) {
	float fval = ((float) in_len + (in_len % 2)) * 0.5;
	size_t ret = (unsigned int) fval;

	ret = (unsigned int) fval;
	ret += ((fval - ((float) ret)) > 0) ? 1 : 0;

	return ret;
}

unsigned char *base16_decode(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	int i = 0, align = 0;
	const uint8_t *work = (const uint8_t *) in;

	if (!out) {
		if (!(out = malloc(base16_decode_size(in_len))))
			return NULL;
	}

	if (in_len % 2) {
		out[0] = _hex_char_to_nibble(work[0]);
		work = (const uint8_t *) &in[align = 1];
		in_len --;
	}

	for (i = 0; (i * 2) < in_len; i ++)
		out[i + align] = (_hex_char_to_nibble(work[i * 2]) << 4) | _hex_char_to_nibble(work[(i * 2) + 1]);

	*out_len = i + align;

	return out;
}

