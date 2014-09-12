/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [PANKAKE] interface 
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

#include "ke/pankake/generic.h"

unsigned char *pankake_client_init(
	unsigned char *client_session,
	unsigned char *client_context,
	const char *password,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000, errsv = 0, session_alloc = 0;
	struct pankake_context *ctx = (struct pankake_context *) client_context;
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
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
		if (!(client_session = malloc(PANKAKE_CLIENT_SESSION_SIZE)))
			return NULL;

		session_alloc = 1;
	}

	/* Join client public key with the first half of pwhash */
	if (!(crypt_encrypt_otp(ctx->ikey, &out_len, ctx->pwhash, sizeof(ctx->ikey), NULL, ctx->c_public))) {
		errsv = errno;
		if (session_alloc) free(client_session);
		errno = errsv;
		return NULL;
	}

	/* Craft nonce */
	tc_memset(nonce, 255, sizeof(nonce));
	nonce[sizeof(nonce) - 1] = 254;

	/* Encrypt client token with ikey, producing client challenge */
	if (!(crypt_encrypt_chacha20(client_session + sizeof(ctx->c_public), &out_len, ctx->c_token, sizeof(ctx->c_token), nonce, ctx->ikey))) {
		errsv = errno;
		if (session_alloc) free(client_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend the public key */
	tc_memcpy(client_session, ctx->c_public, sizeof(ctx->c_public));

	/* All good */
	return client_session;
}

unsigned char *pankake_server_init(
	unsigned char *server_session,
	unsigned char *server_context,
	const unsigned char *client_session,
	const unsigned char *pwhash)
{
	int errsv = 0, session_alloc = 0;
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0;

	/* Initialize context */
	ke_ecdh_private(ctx->private, sizeof(ctx->private));
	ke_ecdh_public(ctx->s_public, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private));

	/* Compute DH shared key */
	if (!ke_ecdh_shared(ctx->shared, client_session, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Copy pwhash into context */
	tc_memcpy(ctx->pwhash, pwhash, sizeof(ctx->pwhash));

	/* Join client public key with the first half of pwhash */
	if (!(crypt_encrypt_otp(ctx->ikey, &out_len, ctx->pwhash, sizeof(ctx->ikey), NULL, client_session)))
		return NULL;

	/* Craft nonce */
	tc_memset(nonce, 255, sizeof(nonce));
	nonce[sizeof(nonce) - 1] = 254;

	/* Encrypt client token with ikey, producing client challenge */
	if (!(crypt_decrypt_chacha20(ctx->c_token, &out_len, client_session + sizeof(ctx->c_public), sizeof(ctx->c_token), nonce, ctx->ikey)))
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(ctx->s_token, sizeof(ctx->s_token)))
		return NULL;

	/* Allocate enough memory for server session, if required */
	if (!server_session) {
		if (!(server_session = malloc(PANKAKE_SERVER_SESSION_SIZE)))
			return NULL;

		session_alloc = 1;
	}

	/* Set nonce to the maximum possible value */
	tc_memset(nonce, 255, sizeof(nonce));

	/* Encrypt client token with first half of pwhash */
	if (!crypt_encrypt_chacha20(server_session + sizeof(ctx->s_public), &out_len, ctx->c_token, sizeof(ctx->c_token), nonce, ctx->ikey)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Join client public key with the second half of pwhash */
	if (!(crypt_encrypt_otp(ctx->ikey, &out_len, ctx->pwhash + sizeof(ctx->ikey), sizeof(ctx->ikey), NULL, client_session))) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Encrypt the server token with ikey */
	if (!crypt_encrypt_chacha20(server_session + sizeof(ctx->s_public) + sizeof(ctx->c_token), &out_len, ctx->s_token, sizeof(ctx->s_token), nonce, ctx->ikey)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend the server public key */
	tc_memcpy(server_session, ctx->s_public, sizeof(ctx->s_public));

	/* All good */
	return server_session;
}

unsigned char *pankake_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session)
{
	int errsv = 0, auth_alloc = 0;
	unsigned char c_token[32];
	unsigned char cs_secret[32];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[256 + 1];
	struct pankake_context *ctx = (struct pankake_context *) client_context;
	size_t out_len = 0, pw_len = 0;

	/* Compute DH shared key */
	if (!ke_ecdh_shared(ctx->shared, server_session, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Set nonce to the maximum possible value to match the server nonce */
	tc_memset(nonce, 255, sizeof(nonce));

	/* Decrypt server auth with ikey */
	if (!crypt_decrypt_chacha20(c_token, &out_len, server_session + sizeof(ctx->s_public), sizeof(c_token), nonce, ctx->ikey))
		return NULL;

	/* Compare the received token with the locally generated token */
	if (tc_memcmp(c_token, ctx->c_token, sizeof(ctx->c_token)))
		return NULL;

	/* Join client public key with the second half of pwhash */
	if (!(crypt_encrypt_otp(ctx->ikey, &out_len, ctx->pwhash + sizeof(ctx->ikey), sizeof(ctx->ikey), NULL, ctx->c_public)))
		return NULL;

	/* Decrypt server token with ikey */
	if (!crypt_decrypt_chacha20(ctx->s_token, &out_len, server_session + sizeof(ctx->s_public) + sizeof(ctx->c_token), sizeof(ctx->s_token), nonce, ctx->ikey))
		return NULL;

	/* Join the client and server token to create the cs_secret */
	if (!crypt_encrypt_otp(cs_secret, &out_len, ctx->c_token, sizeof(ctx->c_token), NULL, ctx->s_token))
		return NULL;

	/* Encrypt the shared key with cs_secret to create the agreed key */
	if (!crypt_encrypt_chacha20(key_agreed, &out_len, ctx->shared, sizeof(ctx->shared), nonce, cs_secret))
		return NULL;

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

int pankake_server_authorize(
	unsigned char *server_context,
	unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000;
	unsigned char cs_secret[32];
	unsigned char pwhash_c[HASH_DIGEST_SIZE_SHA512];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[256 + 1];
	unsigned char *password = &pw_payload[1];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0, pw_len = 0;

	/* Set nonce to 2**sizeof(nonce) - 2 */
	tc_memset(nonce, 255, sizeof(nonce));

	/* Join the client and server token to create the cs_secret */
	if (!crypt_encrypt_otp(cs_secret, &out_len, ctx->c_token, sizeof(ctx->c_token), NULL, ctx->s_token))
		return -1;

	/* Encrypt the shared key with cs_secret to create the agreed key */
	if (!crypt_encrypt_chacha20(key_agreed, &out_len, ctx->shared, sizeof(ctx->shared), nonce, cs_secret))
		return -1;

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

