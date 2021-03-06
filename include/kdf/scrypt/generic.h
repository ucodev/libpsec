/*
 * @file generic.h
 * @brief PSEC Library
 *        scrypt Key Derivation Function interface header
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

#ifndef LIBPSEC_KDF_SCRYPT_LOW_H
#define LIBPSEC_KDF_SCRYPT_LOW_H

#include <stdio.h>
#include <stdint.h>

/* Prototypes */
unsigned char *scrypt_low_do(
	unsigned char *out,
	const unsigned char *pw,
	size_t pw_len,
	const unsigned char *salt,
	size_t salt_len,
	uint64_t n,
	uint32_t r,
	uint32_t p,
	size_t out_size);

#endif
