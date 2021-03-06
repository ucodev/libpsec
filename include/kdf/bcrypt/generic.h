/*
 * @file generic.h
 * @brief PSEC Library
 *        bcrypt Key Derivation Function interface header
 *
 * Date: 10-09-2014
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

#ifndef LIBPSEC_KDF_BCRYPT_LOW_H
#define LIBPSEC_KDF_BCRYPT_LOW_H

#include <stdio.h>
#include <stdint.h>

/* Prototypes */
unsigned char *bcrypt_low_do(
	unsigned char *out,
	unsigned int cost,
	const unsigned char *key,
	size_t key_len,
	const unsigned char salt[16]);

#endif
