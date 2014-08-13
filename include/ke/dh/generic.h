/*
 * @file generic.h
 * @brief PSEC Library
 *        Key Exchange [DH] interface header
 *
 * Date: 13-08-2014
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

#ifndef LIBPSEC_GENERIC_KE_DH_H
#define LIBPSEC_GENERIC_KE_DH_H

#include <stdio.h>


/* Prototypes */
unsigned char *dh_init_private_key(unsigned char *priv, size_t priv_size);
unsigned char *dh_compute_public_key(
	unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size);
unsigned char *dh_compute_shared_key(
	unsigned char *shared,
	const unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size);

#endif
