/*
 * @file generic.c
 * @brief PSEC Library
 *        Constant Time [Memory Operations] interface 
 *
 * Date: 01-09-2014
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

int memcmp_timec(const void *s1, const void *s2, size_t n) {
	size_t i = 0, match = 0;
	const unsigned char *a1 = s1, *a2 = s2;

	for (i = 0, match = 0; i < n; i ++)
		match += (a1[i] == a2[i]) + 1; /* Avoid add 0, reg */

	return match != (n << 1);
}

void *memcpy_timec(void *dest, const void *src, size_t n) {
	unsigned char *d = dest;
	const unsigned char *s = src;

	while (n --) d[n] = s[n];

	return dest;
}

static void *_memmove_fw_timec(void *dest, const void *src, size_t n) {
	unsigned char *d = dest;
	const unsigned char *s = src;
	int i = 0, z = 0;

	for (i = 0, z = -- n; i <= n; i ++) d[i] = s[i];

	return dest;
}

static void *_memmove_bw_timec(void *dest, const void *src, size_t n) {
	unsigned char *d = dest;
	const unsigned char *s = src;
	int i = 0, z = 0;

	for (i = -- n, z = 0; z <= i; i --) d[i] = s[i];

	return dest;
}

void *memmove_timec(void *dest, const void *src, size_t n) {
	void *(*f[2]) (void *, const void *, size_t) = { _memmove_bw_timec, _memmove_fw_timec };

	return f[dest <= src](dest, src, n);
}

void *memset_timec(void *s, int c, size_t n) {
	unsigned char *d = s;

	while (n --) d[n] = (unsigned char) c;

	return s;
}

