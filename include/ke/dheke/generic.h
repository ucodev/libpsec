/*
 * @file generic.h
 * @brief PSEC Library
 *        Encrypted Key Exchange [DH-EKE] interface header
 *
 * Date: 24-08-2014
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

#ifndef LIBPSEC_GENERIC_KE_DHEKE_H
#define LIBPSEC_GENERIC_KE_DHEKE_H

#include <stdio.h>

/* Structures */
#pragma pack(push)
#pragma pack(1)
struct dheke_context {
	unsigned char *pwd;
	size_t pwd_len;
	unsigned char *salt;
	size_t salt_len;
	unsigned char *pwhash;
	size_t pwhash_len;
	unsigned char *c_prv;
	unsigned char *c_pub;
	unsigned char *s_prv;
	unsigned char *s_pub;
	unsigned char *shr;
	size_t prv_len;
	size_t pub_len;
	unsigned int use_mac;
};
#pragma pack(pop)

/* Sizes */
#define DHEKE_CONTEXT_SIZE		sizeof(struct dheke_context)
#define DHEKE_SESSION_EXTRA_SIZE	16

/* Prototypes */
unsigned char *dheke_client_init(
	unsigned char *client_session,
	unsigned char *context,
	const unsigned char *pwd,
	size_t pwd_len,
	const unsigned char *salt,
	size_t salt_len,
	size_t prv_len,
	size_t pub_len,
	unsigned int pbkdf2_rounds,
	unsigned int use_mac);
unsigned char *dheke_server_init(
	unsigned char *server_session,
	unsigned char *key,
	unsigned char *context,
	const unsigned char *client_session,
	const unsigned char *pwd,
	size_t pwd_len,
	const unsigned char *salt,
	size_t salt_len,
	size_t prv_len,
	size_t pub_len,
	unsigned int pbkdf2_rounds,
	unsigned int use_mac);
unsigned char *dheke_client_process(
	unsigned char *key,
	unsigned char *context,
	const unsigned char *server_session);

#endif

