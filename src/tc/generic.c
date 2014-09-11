/*
 * @file generic.c
 * @brief PSEC Library
 *        Time Constant interface 
 *
 * Date: 11-09-2014
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

#include "tc/mem/generic.h"

/* Memory Operations Interface */
int tc_memcmp(const void *s1, const void *s2, size_t n) {
	return memcmp_timec(s1, s2, n);
}

void *tc_memcpy(void *dest, const void *src, size_t n) {
	return memcpy_timec(dest, src, n);
}

void *tc_memmove(void *dest, const void *src, size_t n) {
	return memmove_timec(dest, src, n);
}

void *tc_memset(void *s, int c, size_t n) {
	return memset_timec(s, c, n);
}

void *tc_memxor(void *dest, const void *src, size_t n) {
	return memxor_timec(dest, src, n);
}


