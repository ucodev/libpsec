/*
 * @file generic.h
 * @brief PSEC Library
 *        Key Exchange [PANKAKE] interface header
 *
 * Date: 12-09-2014
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

#ifndef LIBPSEC_GENERIC_KE_PANKAKE_H
#define LIBPSEC_GENERIC_KE_PANKAKE_H

#include <stdio.h>

/* Structures */
#pragma pack(push)
#pragma pack(1)
struct pankake_context {
	unsigned char private[32];
	unsigned char shared[32];
	unsigned char c_public[32];
	unsigned char s_public[32];
	unsigned char c_token[32];
	unsigned char s_token[32];
	unsigned char pwhash[64];
	unsigned char ikey[32];
	char password[256];
};
#pragma pack(pop)

/* Sizes */
#define PANKAKE_KEY_SIZE		32
#define PANKAKE_CONTEXT_SIZE		sizeof(struct pankake_context)
#define PANKAKE_CLIENT_AUTH_SIZE	1 + 256
					/* pw_size, password */
#define PANKAKE_CLIENT_SESSION_SIZE	32 + 32
					/* public key, token */
#define PANKAKE_SERVER_SESSION_SIZE	32 + 32 + 32
					/* public key, ctoken, stoken */

/* Prototypes */
unsigned char *pankake_client_init(
	unsigned char *client_session,
	unsigned char *client_context,
	const char *password,
	const unsigned char *salt,
	size_t salt_len);
unsigned char *pankake_server_init(
	unsigned char *server_session,
	unsigned char *server_context,
	const unsigned char *client_session,
	const unsigned char *pwhash);
unsigned char *pankake_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session);
int pankake_server_authorize(
	unsigned char *server_context,
	unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *salt,
	size_t salt_len);

#endif

