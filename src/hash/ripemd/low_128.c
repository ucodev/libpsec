/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [RIPEMD] low level interface
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

#include "hash/ripemd/low.h"
#include "hash/ripemd/rmd128.h"

#include "tc.h"

/* RIPEMD-128 Low Level Interface */
int ripemd128_low_init(ripemd128_state *context) {
	tc_memset(context, 0, sizeof(ripemd128_state));

	RIPEMD128_init(context->digest);

	return 0;
}

int ripemd128_low_update(ripemd128_state *context, const unsigned char *in, size_t in_len) {
	int i = 0;

	context->mlen += in_len;

	if (context->blen && ((context->blen + in_len) >= sizeof(context->block))) {
		tc_memcpy(&context->block[context->blen], in, sizeof(context->block) - context->blen);

		RIPEMD128_compress(context->digest, (uint32_t *) context->block);

		in_len -= sizeof(context->block) - context->blen;
		in += sizeof(context->block) - context->blen;

		context->blen = 0;

		if (!in_len)
			return 0;

	}

	if (context->blen || (in_len < sizeof(context->block))) {
		tc_memcpy(&context->block[context->blen], in, in_len);
		context->blen += in_len;

		return 0;
	}

	for (context->blen = 0, i = in_len; i >= sizeof(context->block); i -= sizeof(context->block)) {
		RIPEMD128_compress(context->digest, (uint32_t *) in);

		in += sizeof(context->block);
	}

	context->blen = i;

	tc_memcpy(context->block, in, context->blen);

	return 0;
}

int ripemd128_low_final(ripemd128_state *context, unsigned char *out) {
	int i = 0;

	RIPEMD128_finish(context->digest, context->block, context->mlen, 0);

	for (i = 0; i < sizeof(context->digest); i += 4) {
		out[i]     = context->digest[i >> 2];
		out[i + 1] = context->digest[i >> 2] >> 8;
		out[i + 2] = context->digest[i >> 2] >> 16;
		out[i + 3] = context->digest[i >> 2] >> 24;
	}

	return 0;
}

