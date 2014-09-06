/*
 * @file low.c
 * @brief PSEC Library
 *        HASH [TIGER] low level interface
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

#include "hash/tiger/tiger.h"
#include "hash/tiger/low.h"

/* TIGER Low Level Interface */
int tiger_low_init(tiger_state *context) {
	tiger_init(context);

	return 0;
}

int tiger_low_set_passes(tiger_state *context, unsigned int passes) {
	tiger_set_passes(context, passes);

	return 0;
}

int tiger_low_update(tiger_state *context, const unsigned char *in, size_t in_len) {
	tiger_update(context, in, in_len);

	return 0;
}

int tiger_low_final(tiger_state *context, unsigned char *out) {
	tiger_finish(context, out);

	return 0;
}

