/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [MD2] low level interface
 *
 * Date: 04-09-2014
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

#include "hash/md2/low.h"

/* MD2 Low Level Interface */
int md2_low_init(MD2_CTX *context) {
	MD2Init(context);

	return 0;
}

int md2_low_update(MD2_CTX *context, const unsigned char *in, size_t in_len) {
	MD2Update(context, in, in_len);

	return 0;
}

int md2_low_final(MD2_CTX *context, unsigned char *out) {
	MD2Final(out, context);

	return 0;
}

