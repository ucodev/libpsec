/*
 * @file ke.h
 * @brief PSEC Library
 *        Key Exchange interface header
 *
 * Date: 14-09-2014
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

#ifndef LIBPSEC_KE_H
#define LIBPSEC_KE_H

#include <stdio.h>

/* Prototypes */
/****************/
/* DH Interface */
/****************/
unsigned char *ke_dh_private(unsigned char *priv, size_t size);
unsigned char *ke_dh_public(unsigned char *pub, size_t pub_size, const unsigned char *priv, size_t priv_size);
unsigned char *ke_dh_shared(unsigned char *shared, const unsigned char *pub, size_t pub_size, const unsigned char *priv, size_t priv_size);
/********************/
/* DH-EKE Interface */
/********************/
#define KE_CONTEXT_SIZE_DHEKE		((sizeof(unsigned char *) * 8) + (sizeof(size_t) * 5) + sizeof(unsigned int))
#define KE_EXTRA_SESSION_SIZE_DHEKE	16 /* Poly1305 */
unsigned char *ke_dheke_client_init(
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
unsigned char *ke_dheke_server_init(
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
unsigned char *ke_dheke_client_process(
	unsigned char *key,
	unsigned char *context,
	const unsigned char *server_session);
/****************/
/* ECDH Interface */
/****************/
unsigned char *ke_ecdh_private(unsigned char *priv, size_t size);
unsigned char *ke_ecdh_public(unsigned char *pub, size_t pub_size, const unsigned char *priv, size_t priv_size);
unsigned char *ke_ecdh_shared(unsigned char *shared, const unsigned char *pub, size_t pub_size, const unsigned char *priv, size_t priv_size);
/*********************/
/* CHREKE Interface */
/*********************/
#define KE_KEY_SIZE_CHREKE		32
#define KE_CONTEXT_SIZE_CHREKE		(5 * 32) + 64 + 256
#define KE_CLIENT_AUTH_SIZE_CHREKE	256 + 1
#define KE_CLIENT_SESSION_SIZE_CHREKE	32 + 32
#define KE_SERVER_SESSION_SIZE_CHREKE	32 + 32
unsigned char *ke_chreke_client_init(
	unsigned char *client_session,
	unsigned char *client_context,
	const char *password,
	const unsigned char *salt,
	size_t salt_len);
unsigned char *ke_chreke_server_init(
	unsigned char *server_session,
	unsigned char *server_context,
	const unsigned char *client_session,
	const unsigned char *pwhash);
unsigned char *ke_chreke_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session);
int ke_chreke_server_authorize(
	unsigned char *server_context,
	unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *salt,
	size_t salt_len);
/********************/
/* Common Interface */
/********************/
void ke_destroy(unsigned char *key);

#endif

