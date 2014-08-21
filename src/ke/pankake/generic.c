/*
 * @file generic.c
 * @brief PSEC Library
 *        Key Exhange [PANKAKE] interface 
 *
 * Date: 21-08-2014
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
	if ((pw_len = strlen(password)) >= sizeof(password))
		return NULL;

	strcpy(ctx->password, password);

	/* Initialize context */
	ke_dh_private(ctx->private, sizeof(ctx->private));
	ke_dh_public(ctx->c_public, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private));

	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(ctx->pwhash, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, strlen(password), salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return NULL;

	/* Reduce the password hash to match the token size */
	if (!hash_buffer_blake2s(ctx->pwrehash, ctx->pwhash, sizeof(ctx->pwhash)))
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(ctx->token, sizeof(ctx->token)))
		return NULL;

	/* Allocate session memory, if required */
	if (!client_session) {
		if (!(client_session = malloc(sizeof(ctx->c_public) + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt token with the re-hashed version of password hash */
	if (!crypt_encrypt_otp(client_session + sizeof(ctx->c_public), &out_len, ctx->token, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash)) {
		errno = errsv;
		if (session_alloc) free(client_session);
		errsv = errno;
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
	int rounds = 5000, errsv = 0, session_alloc = 0;
	unsigned char server_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash_tmp[HASH_DIGEST_SIZE_SHA512 * 2];
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0;

	/* Initialize context */
	ke_dh_private(ctx->private, sizeof(ctx->private));
	ke_dh_public(ctx->s_public, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private));

	/* Copy pwhash into context */
	memcpy(ctx->pwhash, pwhash, sizeof(ctx->pwhash));

	/* Reduce the password hash to match the token size */
	if (!hash_buffer_blake2s(ctx->pwrehash, ctx->pwhash, HASH_DIGEST_SIZE_SHA512))
		return NULL;

	/* Decrypt token with the re-hashed version of password hash */
	if (!crypt_decrypt_otp(ctx->token, &out_len, client_session + sizeof(ctx->c_public), HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash))
		return NULL;

	/* Compute DH shared key */
	if (!ke_dh_shared(ctx->shared, client_session, sizeof(ctx->c_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Generate the temporary client hash */
	if (!kdf_pbkdf2_hash(secret_hash_tmp, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, pwhash, HASH_DIGEST_SIZE_SHA512, ctx->token, HASH_DIGEST_SIZE_BLAKE2S, rounds, sizeof(secret_hash_tmp)) < 0)
		return NULL;

	/* Reduce temporary client hash */
	if (!hash_buffer_blake2s(ctx->secret_hash, secret_hash_tmp, sizeof(secret_hash_tmp)))
		return NULL;

	/* Encrypt client hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(server_token, &out_len, ctx->secret_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->pwrehash))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(ctx->shared_hash, ctx->shared, sizeof(ctx->shared)))
		return NULL;

	/* Generate a pseudo random nonce */
	if (!generate_bytes_random(nonce, sizeof(nonce)))
		return NULL;

	/* Allocate enough memory for server session, if required */
	if (!server_session) {
		if (!(server_session = malloc(sizeof(ctx->s_public) + CRYPT_NONCE_SIZE_XSALSA20 + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt server token with rehashed version of shared key */
	if (!crypt_encrypt_xsalsa20(server_session + sizeof(ctx->s_public) + CRYPT_NONCE_SIZE_XSALSA20, &out_len, server_token, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend nonce */
	memcpy(server_session + sizeof(ctx->s_public), nonce, sizeof(nonce));

	/* Prepend public key */
	memcpy(server_session, ctx->s_public, sizeof(ctx->s_public));

	/* Cleanup */
	memset(server_token, 0, sizeof(server_token));
	memset(secret_hash_tmp, 0, sizeof(secret_hash_tmp));
	memset(nonce, 0, sizeof(nonce));

	/* All good */
	return server_session;
}

unsigned char *pankake_client_authorize(
	unsigned char *client_auth,
	unsigned char *client_context,
	unsigned char *key_agreed,
	const unsigned char *server_session)
{
	int rounds = 5000, errsv = 0, auth_alloc = 0;
	unsigned char pwrehash_s[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char server_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash_tmp[HASH_DIGEST_SIZE_SHA512 * 2];
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	unsigned char pw_payload[256 + 1];
	struct pankake_context *ctx = (struct pankake_context *) client_context;
	size_t out_len = 0, pw_len = 0;

	/* Generate the temporary client hash */
	if (!kdf_pbkdf2_hash(secret_hash_tmp, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, ctx->pwhash, HASH_DIGEST_SIZE_SHA512, ctx->token, HASH_DIGEST_SIZE_BLAKE2S, rounds, sizeof(secret_hash_tmp)) < 0)
		return NULL;

	/* Reduce temporary client hash */
	if (!hash_buffer_blake2s(ctx->secret_hash, secret_hash_tmp, sizeof(secret_hash_tmp)))
		return NULL;

	/* Compute DH shared key */
	if (!ke_dh_shared(ctx->shared, server_session, sizeof(ctx->s_public), ctx->private, sizeof(ctx->private)))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(ctx->shared_hash, ctx->shared, sizeof(ctx->shared)))
		return NULL;

	/* Extract nonce */
	memcpy(nonce, server_session + sizeof(ctx->s_public), sizeof(nonce));

	/* Decrypt server token with rehashed version of shared key */
	if (!crypt_decrypt_xsalsa20(server_token, &out_len, server_session + sizeof(ctx->s_public) + CRYPT_NONCE_SIZE_XSALSA20, HASH_DIGEST_SIZE_BLAKE2S, nonce, ctx->shared_hash))
		return NULL;

	/* Decrypt the server token with client hash in order to retrieve the server rehashed version
	 * of pwhash.
	 */
	if (!crypt_decrypt_otp(pwrehash_s, &out_len, server_token, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->secret_hash))
		return NULL;

	/* Compare both rehashed version */
	if (memcmp(pwrehash_s, ctx->pwrehash, HASH_DIGEST_SIZE_BLAKE2S))
		return NULL;

	/* Encrypt client hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(key_agreed, &out_len, ctx->shared_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->secret_hash))
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

	/* Generate a new nonce */
	if (!generate_bytes_random(nonce, sizeof(nonce)))
		return NULL;

	/* Allocate client auth memory if required */
	if (!client_auth) {
		if (!(client_auth = malloc(CRYPT_NONCE_SIZE_XSALSA20 + sizeof(pw_payload))))
			return NULL;

		auth_alloc = 1;
	}

	/* Encrypt pw_payload to create the client auth */
	if (!crypt_encrypt_xsalsa20(client_auth + CRYPT_NONCE_SIZE_XSALSA20, &out_len, pw_payload, sizeof(pw_payload), nonce, key_agreed)) {
		errsv = errno;
		if (auth_alloc) free(client_auth);
		errno = errsv;
		return NULL;
	}

	/* Copy nonce into client_auth */
	memcpy(client_auth, nonce, sizeof(nonce));

	/* Cleanup */
	memset(pwrehash_s, 0, sizeof(pwrehash_s));
	memset(server_token, 0, sizeof(server_token));
	memset(secret_hash_tmp, 0, sizeof(secret_hash_tmp));
	memset(nonce, 0, sizeof(nonce));

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
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	unsigned char pw_payload[256 + 1];
	unsigned char *password = &pw_payload[1];
	struct pankake_context *ctx = (struct pankake_context *) server_context;
	size_t out_len = 0, pw_len = 0;

	/* Encrypt secret hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(key_agreed, &out_len, ctx->shared_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, ctx->secret_hash))
		return -1;

	/* Extract nonce */
	memcpy(nonce, client_auth, CRYPT_NONCE_SIZE_XSALSA20);

	/* Encrypt pw_payload to create the client auth */
	if (!crypt_decrypt_xsalsa20(pw_payload, &out_len, client_auth + CRYPT_NONCE_SIZE_XSALSA20, sizeof(pw_payload), nonce, key_agreed))
		return -1;

	/* Set password length */
	pw_len = pw_payload[0];
	
	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(pwhash_c, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, pw_len, salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return -1;

	/* Compare hashes */
	if (memcmp(ctx->pwhash, pwhash_c, HASH_DIGEST_SIZE_SHA512))
		return -1;

	/* Cleanup */
	memset(pwhash_c, 0, sizeof(pwhash_c));
	memset(nonce, 0, sizeof(nonce));
	memset(pw_payload, 0, sizeof(pw_payload));

	/* All good */
	return 0;
}

