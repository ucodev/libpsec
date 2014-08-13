/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange interface 
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

#include <stdio.h>
#include <stdlib.h>

#include "ke/dh/generic.h"

#include "ke.h"

/* DH Interface */
unsigned char *ke_dh_private(unsigned char *priv, size_t size) {
	return dh_init_private_key(priv, size);
}

unsigned char *ke_dh_public(
	unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	return dh_compute_public_key(pub, pub_size, priv, priv_size);
}

unsigned char *ke_dh_shared(
	unsigned char *shared,
	const unsigned char *pub,
	size_t pub_size,
	const unsigned char *priv,
	size_t priv_size)
{
	return dh_compute_shared_key(shared, pub, pub_size, priv, priv_size);
}

/********************/
/* Common Interface */
/********************/
void ke_destroy(unsigned char *key) {
	free(key);
}

