/*
 * @file format.c
 * @brief PSEC Library
 *        HASH formatting interface 
 *
 * Date: 02-08-2014
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
#include <stdint.h>
#include <stdlib.h>

static char _nibble_to_hex_char(uint8_t nibble) {
	if (nibble > 15)
		return (char) 0;

	return (char) nibble + (nibble < 10 ? 48 : 87);
}

char *hash_format_create_hex(const char *digest, size_t len) {
	int i = 0;
	char *fmt_digest = NULL;

	if (!(fmt_digest = malloc((len * 2) + 1)))
		return NULL;

	memset(fmt_digest, 0, (len * 2) + 1);

	for (i = 0; i < len; i ++) {
		fmt_digest[(i * 2)] = _nibble_to_hex_char((digest[i] & 0xf0) >> 4);
		fmt_digest[(i * 2) + 1] = _nibble_to_hex_char(digest[i] & 0x0f);
	}

	return fmt_digest;
}

void hash_format_destroy(char *fmt_digest) {
	free(fmt_digest);
}

