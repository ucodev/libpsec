/*
 * @file generic.c
 * @brief PSEC Library
 *        Architecture Specific portable [SPEC] interface 
 *
 * Date: 08-09-2014
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

#include <string.h>
#include <stdint.h>

#include "tc.h"

static inline int _is_little(void) {
	uint16_t u = 1;
	unsigned char v[2];

	tc_memcpy(v, &u, 2);

	return v[0];
}

int spec_endianness_is_little(void) {
	return _is_little();
}

int spec_endianness_is_big(void) {
	return !_is_little();
}

