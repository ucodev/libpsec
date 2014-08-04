/*
 * @file generic.c
 * @brief PSEC Library
 *        Base64 Encoding interface 
 *
 * Date: 04-08-2014
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

#include "generic.h"


char *base64_encode(char *out, const char *in, size_t in_len) {
	int i = 0, j = 0, left = 0;
	char align[3] = { 0, 0, 0 };
	const char *work = in;

	for (i = 0, j = 0; (i + 3) <= in_len; i += 3, j += 4) {
		out[j]     = _base64_index[work[i] >> 2];
		out[j + 1] = _base64_index[((work[i] & 0x03) << 4) | (work[i + 1] >> 4)];
		out[j + 2] = _base64_index[((work[i + 1] & 0x0f) << 2) | (work[i + 2] >> 6)];
		out[j + 3] = _base64_index[work[i + 2] & 0x3f];
	}

	if (!(left = in_len - i))
		return out;

	memcpy(align, &in[i], left);
	work = align;
	i = 0;

	switch (left) {
		case 2: out[j + 2] = _base64_index[((work[i + 1] & 0x0f) << 2) | (work[i + 2] >> 6)];
		case 1: out[j] = _base64_index[work[i] >> 2];
			out[j + 1] = _base64_index[((work[i] & 0x03) << 4) | (work[i + 1] >> 4)];
			out[j + 3] = '=';
			if (left == 1) out[j + 2] = '=';
	}

	return out;
}

