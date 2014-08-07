/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [MD4] low level interface
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

#include "hash/md4/low.h"

/* MD4 Low Level Interface */
int md4_low_init(MD4_CTX *context) {
	MD4Init(context);

	return 0;
}

int md4_low_update(MD4_CTX *context, const unsigned char *in, size_t in_len) {
	MD4Update(context, in, in_len);

	return 0;
}

int md4_low_final(MD4_CTX *context, unsigned char *out) {
	MD4Final(out, context);

	return 0;
}

