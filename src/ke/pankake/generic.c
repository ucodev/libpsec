/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [PANKAKE] interface 
 *
 * Date: 26-08-2014
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
	size_t out_len = 0, pw_len = 0;

	/* Check password length */
	if ((pw_len = strlen(password)) >= sizeof(ctx->password))
		return NULL;

	strcpy(ctx->password, password);

	/* Initialize context */
	ke_dh_private(ctx->private, sizeof(ctx->private));
	ke_dh_public(ctx->c_public, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private));

	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(ctx->pwhash, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, strlen(password), salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return NULL;

	/* Re-hash the first half of the password hash */
	if (!hash_buffer_blake2s(ctx->pwrehash_l, ctx->pwhash, sizeof(ctx->pwhash) >> 1))
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(ctx->c_token, sizeof(ctx->c_token)))
		return NULL;

	/* Allocate session memory, if required */
	if (!client_session) {
		if (!(client_session = malloc(sizeof(ctx->c_public) + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt token with the re-hashed version of password hash */
	if (!crypt_encrypt_otp(client_session + sizeof(ctx->c_public), &out_len, ctx->c_token, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash_l)) {
		errsv = errno;
		if (session_alloc) free(client_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend the public key */
	memcpy(client_session, ctx->c_public, sizeof(ctx->c_public));

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
	unsigned char server_auth[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0;

	/* Initialize context */
	ke_dh_private(ctx->private, sizeof(ctx->private));
	ke_dh_public(ctx->s_public, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private));

	/* Copy pwhash into context */
	memcpy(ctx->pwhash, pwhash, sizeof(ctx->pwhash));

	/* Re-hash the first half of the password hash */
	if (!hash_buffer_blake2s(ctx->pwrehash_l, ctx->pwhash, HASH_DIGEST_SIZE_SHA512 >> 1))
		return NULL;

	/* Decrypt token with the re-hashed version of password hash */
	if (!crypt_decrypt_otp(ctx->c_token, &out_len, client_session + sizeof(ctx->c_public), HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash_l))
		return NULL;

	/* Compute DH shared key */
	if (!ke_dh_shared(ctx->shared, client_session, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(ctx->s_token, sizeof(ctx->s_token) - CRYPT_EXTRA_SIZE_CHACHA20POLY1305))
		return NULL;

	/* Set nonce to the maximum possible value */
	memset(nonce, 255, sizeof(nonce));

	/* Encrypt token with the re-hashed version of password hash */
	if (!crypt_encrypt_chacha20poly1305(ctx->secret_hash, &out_len, ctx->s_token, sizeof(ctx->s_token) - CRYPT_EXTRA_SIZE_CHACHA20POLY1305, nonce, ctx->c_token))
		return NULL;

	/* Re-hash the second half of the password hash */
	if (!hash_buffer_blake2s(ctx->pwrehash_h, ctx->pwhash + (HASH_DIGEST_SIZE_SHA512 >> 1), HASH_DIGEST_SIZE_SHA512 >> 1))
		return NULL;

	/* Encrypt client hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(server_auth, &out_len, ctx->secret_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash_h))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(ctx->shared_hash, ctx->shared, sizeof(ctx->shared)))
		return NULL;

	/* Allocate enough memory for server session, if required */
	if (!server_session) {
		if (!(server_session = malloc(sizeof(ctx->s_public) + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt server token with rehashed version of shared key */
	if (!crypt_encrypt_chacha20(server_session + sizeof(ctx->s_public), &out_len, server_auth, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend public key */
	memcpy(server_session, ctx->s_public, sizeof(ctx->s_public));

	/* Cleanup */
	memset(server_auth, 0, sizeof(server_auth));

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
	unsigned char server_auth[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[256 + 1];
	struct pankake_context *ctx = (struct pankake_context *) client_context;
	size_t out_len = 0, pw_len = 0;

	/* Compute DH shared key */
	if (!ke_dh_shared(ctx->shared, server_session, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(ctx->shared_hash, ctx->shared, sizeof(ctx->shared)))
		return NULL;

	/* Set nonce to the maximum possible value to match the server nonce */
	memset(nonce, 255, sizeof(nonce));

	/* Decrypt server auth with rehashed version of shared key */
	if (!crypt_decrypt_chacha20(server_auth, &out_len, server_session + sizeof(ctx->s_public), HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash))
		return NULL;

	/* Re-hash the second half of the password hash */
	if (!hash_buffer_blake2s(ctx->pwrehash_h, ctx->pwhash + (HASH_DIGEST_SIZE_SHA512 >> 1), HASH_DIGEST_SIZE_SHA512 >> 1))
		return NULL;

	/* Decrypt the secret hash with rehashed version of pwhash */
	if (!crypt_decrypt_otp(ctx->secret_hash, &out_len, server_auth, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash_h))
		return NULL;

	/* Try to decrypt the secret hash. If verification fails, server isn't legit */
	if (!crypt_decrypt_chacha20poly1305(ctx->s_token, &out_len, ctx->secret_hash, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->c_token))
		return NULL;

	/* Set nonce to 2**sizeof(nonce) - 2 */
	memset(nonce, 255, sizeof(nonce));
	nonce[sizeof(nonce) - 1] = 254;

	/* Encrypt secret hash with the dh shared key to create the agreed key */
	if (!crypt_encrypt_chacha20(key_agreed, &out_len, ctx->secret_hash, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash))
		return NULL;

	/* Check if password is within acceptable limits */
	if ((pw_len = strlen(ctx->password)) > 255)
		return NULL;

	/* Fill the password payload with pseudo random data */
	if (!generate_bytes_random(pw_payload, sizeof(pw_payload)))
		return NULL;

	/* Copy the password into the pw payload */
	memcpy(pw_payload + 1, ctx->password, pw_len);

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

	/* Cleanup */
	memset(server_auth, 0, sizeof(server_auth));

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
	unsigned char pwhash_c[HASH_DIGEST_SIZE_SHA512];
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	unsigned char pw_payload[256 + 1];
	unsigned char *password = &pw_payload[1];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0, pw_len = 0;

	/* Set nonce to 2**sizeof(nonce) - 2 */
	memset(nonce, 255, sizeof(nonce));
	nonce[sizeof(nonce) - 1] = 254;

	/* Encrypt secret hash with dh shared key to create the agreed key */
	if (!crypt_encrypt_chacha20(key_agreed, &out_len, ctx->secret_hash, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash))
		return -1;

	/* Decrypt pw_payload to create the client auth */
	if (!crypt_decrypt_chacha20(pw_payload, &out_len, client_auth, sizeof(pw_payload), nonce, key_agreed))
		return -1;

	/* Set password length */
	pw_len = pw_payload[0];
	
	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(pwhash_c, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, pw_len, salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return -1;

	/* Compare hashes */
	if (tc_memcmp(ctx->pwhash, pwhash_c, HASH_DIGEST_SIZE_SHA512))
		return -1;

	/* Cleanup */
	memset(pwhash_c, 0, sizeof(pwhash_c));
	memset(pw_payload, 0, sizeof(pw_payload));

	/* All good */
	return 0;
}

