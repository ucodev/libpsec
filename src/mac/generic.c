/*
 * @file generic.c
 * @brief PSEC Library
 *        Message Authentication Code interface 
 *
 * Date: 03-08-2014
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

#include "mac/hmac/generic.h"

#include "mac.h"

/* HMAC Interface */
char *mac_hmac_hash(
	char *out,
	char *(*hash) (char *out, const char *in, size_t len),
	size_t hash_len,
	size_t hash_block_size,
	const char *key,
	size_t key_len,
	const char *msg,
	size_t msg_len)
{
	return hmac_generic(out, hash, hash_len, hash_block_size, key, key_len, msg, msg_len);
}

void mac_destroy(char *digest) {
	free(digest);
}

