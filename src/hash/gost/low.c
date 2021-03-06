/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [GOST] low level interface
 *
 * Date: 05-09-2014
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

#include "hash/gost/gosthash.h"
#include "hash/gost/low.h"

/* GOST Low Level Interface */
int gost_low_init(GostHashCtx *context) {
	gosthash_reset(context);

	return 0;
}

int gost_low_update(GostHashCtx *context, const unsigned char *in, size_t in_len) {
	gosthash_update(context, in, in_len);

	return 0;
}

int gost_low_final(GostHashCtx *context, unsigned char *out) {
	gosthash_final(context, out);

	return 0;
}

