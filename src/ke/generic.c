/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange interface 
 *
 * Date: 20-08-2014
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
#include "ke/dheke/generic.h"
#include "ke/pankake/generic.h"

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

/* DHEKE Interface */
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
	unsigned int use_mac)
{
	return dheke_client_init(client_session, context, pwd, pwd_len, salt, salt_len, prv_len, pub_len, pbkdf2_rounds, use_mac);
}

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
	unsigned int use_mac)
{
	return dheke_server_init(server_session, key, context, client_session, pwd, pwd_len, salt, salt_len, prv_len, pub_len, pbkdf2_rounds, use_mac);
}

unsigned char *ke_dheke_client_process(
	unsigned char *key,
	unsigned char *context,
	const unsigned char *server_session)
{
	return dheke_client_process(key, context, server_session);
}

/* PANKAKE Interface */
unsigned char *ke_pankake_client_init(
	unsigned char *client_session,
	unsigned char *client_context,
	const char *password,
	const unsigned char *salt,
	size_t salt_len)
{
	return pankake_client_init(client_session, client_context, password, salt, salt_len);
}

unsigned char *ke_pankake_server_init(
	unsigned char *server_session,
	unsigned char *server_context,
	const unsigned char *client_session,
	const unsigned char *pwhash)
{
	return pankake_server_init(server_session, server_context, client_session, pwhash);
}

unsigned char *ke_pankake_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session)
{
	return pankake_client_authorize(client_auth, client_context, key_agreed, server_session);
}

int ke_pankake_server_authorize(
	unsigned char *server_session,
	unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *salt,
	size_t salt_len)
{
	return pankake_server_authorize(server_session, key_agreed, client_auth, salt, salt_len);
}

/********************/
/* Common Interface */
/********************/
void ke_destroy(unsigned char *key) {
	free(key);
}

