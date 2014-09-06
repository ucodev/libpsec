/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [HAVAL256] low level interface
 *
 * Date: 06-09-2014
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

#include "hash/haval/low.h"

/* HAVAL256 Low Level Interface */
int haval256_low_init(haval_state *context) {
	haval_start(context);
	haval_set_fptlen(context, 256);
	haval_set_pass(context, 5);

	return 0;
}

int haval256_low_update(haval_state *context, const unsigned char *in, size_t in_len) {
	haval_hash(context, in, in_len);

	return 0;
}

int haval256_low_final(haval_state *context, unsigned char *out) {
	haval_end(context, out);

	return 0;
}

