/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [CHREKE] interface 
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "generate.h"
#include "hash.h"
#include "kdf.h"
#include "ke.h"
#include "mac.h"
#include "crypt.h"
#include "tc.h"

#include "ke/chreke/generic.h"

unsigned char *chreke_client_init(
	unsigned char *client_session,
	unsigned char *client_context,
	const char *password,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000, errsv = 0, session_alloc = 0;
	struct chreke_context *ctx = (struct chreke_context *) client_context;
	size_t out_len = 0, pw_len = 0;

	/* Check password length */
	if ((pw_len = strlen(password)) >= sizeof(ctx->password))
		return NULL;

	strcpy(ctx->password, password);

	/* Initialize context */
	ke_ecdh_private(ctx->private, sizeof(ctx->private));
	ke_ecdh_public(ctx->c_public, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private));

	/* Generate the password hash */
	if (!kdf_pbkdf2_sha512(ctx->pwhash, (unsigned char *) password, strlen(password), salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(ctx->c_token, sizeof(ctx->c_token)))
		return NULL;

	/* Allocate session memory, if required */
	if (!client_session) {
		if (!(client_session = malloc(CHREKE_CLIENT_SESSION_SIZE)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt public key with pwhash */
	if (!crypt_encrypt_otp(client_session, &out_len, ctx->c_public, sizeof(ctx->c_public), NULL, ctx->pwhash)) {
		errsv = errno;
		if (session_alloc) free(client_session);
		errno = errsv;
		return NULL;
	}

	/* Encrypt token with client public key */
	if (!crypt_encrypt_otp(client_session + sizeof(ctx->c_public), &out_len, ctx->c_token, sizeof(ctx->c_token), NULL, ctx->c_public)) {
		errsv = errno;
		if (session_alloc) free(client_session);
		errno = errsv;
		return NULL;
	}

	/* All good */
	return client_session;
}

unsigned char *chreke_server_init(
	unsigned char *server_session,
	unsigned char *server_context,
	const unsigned char *client_session,
	const unsigned char *pwhash)
{
	int errsv = 0, session_alloc = 0;
	struct chreke_context *ctx = (struct chreke_context *) server_context;
	size_t out_len = 0;

	/* Initialize context */
	ke_ecdh_private(ctx->private, sizeof(ctx->private));
	ke_ecdh_public(ctx->s_public, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private));

	/* Decrypt client public key */
	if (!crypt_decrypt_otp(ctx->c_public, &out_len, client_session, sizeof(ctx->c_public), NULL, pwhash))
		return NULL;

	/* Decrypt client token */
	if (!crypt_decrypt_otp(ctx->c_token, &out_len, client_session + sizeof(ctx->c_public), sizeof(ctx->c_token), NULL, ctx->c_public))
		return NULL;

	/* Compute DH shared key */
	if (!ke_ecdh_shared(ctx->shared, ctx->c_public, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Copy pwhash into context */
	tc_memcpy(ctx->pwhash, pwhash, sizeof(ctx->pwhash));

	/* Allocate enough memory for server session, if required */
	if (!server_session) {
		if (!(server_session = malloc(CHREKE_SERVER_SESSION_SIZE)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt server public key */
	if (!crypt_encrypt_otp(server_session, &out_len, ctx->s_public, sizeof(ctx->s_public), NULL, ctx->pwhash + (HASH_DIGEST_SIZE_SHA512 >> 1))) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Encrypt client token with shared key */
	if (!crypt_encrypt_otp(server_session + sizeof(ctx->s_public), &out_len, ctx->c_token, sizeof(ctx->s_public), NULL, ctx->shared)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* All good */
	return server_session;
}

unsigned char *chreke_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session)
{
	int errsv = 0, auth_alloc = 0;
	unsigned char c_token[32];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[255 + 1];
	struct chreke_context *ctx = (struct chreke_context *) client_context;
	size_t out_len = 0, pw_len = 0;

	/* Decrypt server public key */
	if (!crypt_decrypt_otp(ctx->s_public, &out_len, server_session, sizeof(ctx->s_public), NULL, ctx->pwhash + (HASH_DIGEST_SIZE_SHA512 >> 1)))
		return NULL;

	/* Compute DH shared key */
	if (!ke_ecdh_shared(ctx->shared, ctx->s_public, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Decrypt client token */
	if (!crypt_decrypt_otp(c_token, &out_len, server_session + sizeof(ctx->c_public), sizeof(ctx->c_token), NULL, ctx->shared))
		return NULL;

	/* Compare the received token with the locally generated token */
	if (tc_memcmp(c_token, ctx->c_token, sizeof(ctx->c_token)))
		return NULL;

	/* Copy agreed key */
	tc_memcpy(key_agreed, ctx->shared, sizeof(ctx->shared));

	/* Check if password is within acceptable limits */
	if ((pw_len = strlen(ctx->password)) > 255)
		return NULL;

	/* Fill the password payload with pseudo random data */
	if (!generate_bytes_random(pw_payload, sizeof(pw_payload)))
		return NULL;

	/* Copy the password into the pw payload */
	tc_memcpy(pw_payload + 1, ctx->password, pw_len);

	/* Set the password length in the pw payload */
	pw_payload[0] = pw_len;

	/* Allocate client auth memory if required */
	if (!client_auth) {
		if (!(client_auth = malloc(sizeof(pw_payload))))
			return NULL;

		auth_alloc = 1;
	}

	/* Set nonce */
	tc_memset(nonce, 255, sizeof(nonce));

	/* Encrypt pw_payload to create the client auth.
	 *
	 * NOTE: We use the same nonce because the key is different.
	 *
	 */
	if (!crypt_encrypt_chacha20(client_auth, &out_len, pw_payload, sizeof(pw_payload), nonce, key_agreed)) {
		errsv = errno;
		if (auth_alloc) free(client_auth);
		errno = errsv;
		return NULL;
	}

	/* All good */
	return client_auth;
}

int chreke_server_authorize(
	unsigned char *server_context,
	unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000;
	unsigned char pwhash_c[HASH_DIGEST_SIZE_SHA512];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[255 + 1];
	unsigned char *password = &pw_payload[1];
	struct chreke_context *ctx = (struct chreke_context *) server_context;
	size_t out_len = 0, pw_len = 0;

	/* Copy agreed key */
	tc_memcpy(key_agreed, ctx->shared, sizeof(ctx->shared));

	/* Set nonce */
	tc_memset(nonce, 255, sizeof(nonce));

	/* Decrypt pw_payload to create the client auth */
	if (!crypt_decrypt_chacha20(pw_payload, &out_len, client_auth, sizeof(pw_payload), nonce, key_agreed))
		return -1;

	/* Set password length */
	pw_len = pw_payload[0];
	
	/* Generate the password hash */
	if (!kdf_pbkdf2_sha512(pwhash_c, (unsigned char *) password, pw_len, salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return -1;

	/* Compare hashes */
	if (tc_memcmp(ctx->pwhash, pwhash_c, HASH_DIGEST_SIZE_SHA512))
		return -1;

	/* Cleanup */
	tc_memset(pwhash_c, 0, sizeof(pwhash_c));
	tc_memset(pw_payload, 0, sizeof(pw_payload));

	/* All good */
	return 0;
}

