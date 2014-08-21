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

unsigned char *pankake_client_init(
	unsigned char *client_session,
	const unsigned char *pubkey,
	size_t pubkey_len,
	const char *password,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000, errsv = 0, session_alloc = 0;
	unsigned char pwhash[HASH_DIGEST_SIZE_SHA512];
	unsigned char pwrehash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char token[HASH_DIGEST_SIZE_BLAKE2S];
	size_t out_len = 0;

	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(pwhash, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, strlen(password), salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return NULL;

	/* Reduce the password hash to match the token size */
	if (!hash_buffer_blake2s(pwrehash, pwhash, sizeof(pwhash)))
		return NULL;

	/* Generate a pseudo random token */
	if (!generate_bytes_random(token, sizeof(token)))
		return NULL;

	/* Allocate session memory, if required */
	if (!client_session) {
		if (!(client_session = malloc(pubkey_len + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt token with the re-hashed version of password hash */
	if (!crypt_encrypt_otp(client_session + pubkey_len, &out_len, token, HASH_DIGEST_SIZE_BLAKE2S, NULL, pwrehash)) {
		errno = errsv;
		if (session_alloc) free(client_session);
		errsv = errno;
		return NULL;
	}

	/* Prepend the public key */
	memcpy(client_session, pubkey, pubkey_len);

	/* Cleanup data */
	memset(pwhash, 0, sizeof(pwhash));
	memset(pwrehash, 0, sizeof(pwrehash));
	memset(token, 0, sizeof(token));

	/* All good */
	return client_session;
}

unsigned char *pankake_server_init(
	unsigned char *server_session,
	unsigned char *key_agreed,
	unsigned char *shrkey,
	const unsigned char *pubkey,
	size_t pubkey_len,
	const unsigned char *prvkey,
	size_t prvkey_len,
	const unsigned char *client_session,
	const unsigned char *pwhash)
{
	int rounds = 5000, errsv = 0, session_alloc = 0;
	unsigned char pwrehash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char client_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char server_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash_tmp[HASH_DIGEST_SIZE_SHA512 * 2];
	unsigned char shrkey_hash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	size_t out_len = 0;

	/* Reduce the password hash to match the token size */
	if (!hash_buffer_blake2s(pwrehash, pwhash, HASH_DIGEST_SIZE_SHA512))
		return NULL;

	/* Decrypt token with the re-hashed version of password hash */
	if (!crypt_decrypt_otp(client_token, &out_len, client_session + pubkey_len, HASH_DIGEST_SIZE_BLAKE2S, NULL, pwrehash))
		return NULL;

	/* Compute DH shared key */
	if (!ke_dh_shared(shrkey, client_session, pubkey_len, prvkey, prvkey_len))
		return NULL;

	/* Generate the temporary client hash */
	if (!kdf_pbkdf2_hash(secret_hash_tmp, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, pwhash, HASH_DIGEST_SIZE_SHA512, client_token, HASH_DIGEST_SIZE_BLAKE2S, rounds, sizeof(secret_hash_tmp)) < 0)
		return NULL;

	/* Reduce temporary client hash */
	if (!hash_buffer_blake2s(secret_hash, secret_hash_tmp, sizeof(secret_hash_tmp)))
		return NULL;


	/* Encrypt client hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(server_token, &out_len, secret_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, pwrehash))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(shrkey_hash, shrkey, pubkey_len))
		return NULL;

	/* Generate a pseudo random nonce */
	if (!generate_bytes_random(nonce, sizeof(nonce)))
		return NULL;

	/* Allocate enough memory for server session, if required */
	if (!server_session) {
		if (!(server_session = malloc(pubkey_len + CRYPT_NONCE_SIZE_XSALSA20 + HASH_DIGEST_SIZE_BLAKE2S)))
			return NULL;

		session_alloc = 1;
	}

	/* Encrypt server token with rehashed version of shared key */
	if (!crypt_encrypt_xsalsa20(server_session + pubkey_len + CRYPT_NONCE_SIZE_XSALSA20, &out_len, server_token, HASH_DIGEST_SIZE_BLAKE2S, nonce, shrkey_hash)) {
		errsv = errno;
		if (session_alloc) free(server_session);
		errno = errsv;
		return NULL;
	}

	/* Prepend nonce */
	memcpy(server_session + pubkey_len, nonce, sizeof(nonce));

	/* Prepend public key */
	memcpy(server_session, pubkey, pubkey_len);

	/* Encrypt secret hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(key_agreed, &out_len, shrkey_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, secret_hash))
		return NULL;

	/* Cleanup */
	memset(pwrehash, 0, sizeof(pwrehash));
	memset(client_token, 0, sizeof(client_token));
	memset(server_token, 0, sizeof(server_token));
	memset(secret_hash, 0, sizeof(secret_hash));
	memset(secret_hash_tmp, 0, sizeof(secret_hash_tmp));
	memset(shrkey_hash, 0, sizeof(shrkey_hash));
	memset(nonce, 0, sizeof(nonce));

	/* All good */
	return server_session;
}

unsigned char *pankake_client_authorize(
	unsigned char *client_auth,
	unsigned char *key_agreed,
	unsigned char *shrkey,
	const unsigned char *pubkey,
	size_t pubkey_len,
	const unsigned char *prvkey,
	size_t prvkey_len,
	const unsigned char *server_session,
	const unsigned char *client_session,
	const char *password,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000, errsv = 0, auth_alloc = 0;
	unsigned char pwhash[HASH_DIGEST_SIZE_SHA512];
	unsigned char pwrehash_s[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char pwrehash_c[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char client_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char server_token[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char secret_hash_tmp[HASH_DIGEST_SIZE_SHA512 * 2];
	unsigned char shrkey_hash[HASH_DIGEST_SIZE_BLAKE2S];
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	unsigned char pw_payload[256 + 1];
	size_t out_len = 0, pw_len = 0;

	/* Generate the password hash */
	if (!kdf_pbkdf2_hash(pwhash, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, (unsigned char *) password, strlen(password), salt, salt_len, rounds, HASH_DIGEST_SIZE_SHA512) < 0)
		return NULL;

	/* Reduce the password hash to match the token size */
	if (!hash_buffer_blake2s(pwrehash_c, pwhash, sizeof(pwhash)))
		return NULL;

	/* Decrypt token with the re-hashed version of password hash */
	if (!crypt_decrypt_otp(client_token, &out_len, client_session + pubkey_len, HASH_DIGEST_SIZE_BLAKE2S, NULL, pwrehash_c))
		return NULL;

	/* Generate the temporary client hash */
	if (!kdf_pbkdf2_hash(secret_hash_tmp, hash_buffer_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, pwhash, HASH_DIGEST_SIZE_SHA512, client_token, HASH_DIGEST_SIZE_BLAKE2S, rounds, sizeof(secret_hash_tmp)) < 0)
		return NULL;

	/* Reduce temporary client hash */
	if (!hash_buffer_blake2s(secret_hash, secret_hash_tmp, sizeof(secret_hash_tmp)))
		return NULL;

	/* Compute DH shared key */
	if (!ke_dh_shared(shrkey, server_session, pubkey_len, prvkey, prvkey_len))
		return NULL;

	/* Reduce the DH shared key */
	if (!hash_buffer_blake2s(shrkey_hash, shrkey, pubkey_len))
		return NULL;

	/* Extract nonce */
	memcpy(nonce, server_session + pubkey_len, sizeof(nonce));

	/* Decrypt server token with rehashed version of shared key */
	if (!crypt_decrypt_xsalsa20(server_token, &out_len, server_session + pubkey_len + CRYPT_NONCE_SIZE_XSALSA20, HASH_DIGEST_SIZE_BLAKE2S, nonce, shrkey_hash))
		return NULL;

	/* Decrypt the server token with client hash in order to retrieve the server rehashed version
	 * of pwhash.
	 */
	if (!crypt_decrypt_otp(pwrehash_s, &out_len, server_token, HASH_DIGEST_SIZE_BLAKE2S, NULL, secret_hash))
		return NULL;

	/* Compare both rehashed version */
	if (memcmp(pwrehash_s, pwrehash_c, HASH_DIGEST_SIZE_BLAKE2S))
		return NULL;

	/* Encrypt client hash with rehashed version of pwhash to create the server token */
	if (!crypt_encrypt_otp(key_agreed, &out_len, shrkey_hash, HASH_DIGEST_SIZE_BLAKE2S, NULL, secret_hash))
		return NULL;

	/* Check if password is within acceptable limits */
	if ((pw_len = strlen(password)) > 255)
		return NULL;

	/* Fill the password payload with pseudo random data */
	if (!generate_bytes_random(pw_payload, sizeof(pw_payload)))
		return NULL;

	/* Copy the password into the pw payload */
	memcpy(pw_payload + 1, password, pw_len);

	/* Set the password length in the pw payload */
	pw_payload[0] = pw_len;

	/* Generate a new nonce */
	if (!generate_bytes_random(nonce, sizeof(nonce)))
		return NULL;

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
	memset(pwhash, 0, sizeof(pwhash));
	memset(pwrehash_c, 0, sizeof(pwrehash_c));
	memset(pwrehash_s, 0, sizeof(pwrehash_s));
	memset(client_token, 0, sizeof(client_token));
	memset(server_token, 0, sizeof(server_token));
	memset(secret_hash, 0, sizeof(secret_hash));
	memset(secret_hash_tmp, 0, sizeof(secret_hash_tmp));
	memset(shrkey_hash, 0, sizeof(shrkey_hash));
	memset(nonce, 0, sizeof(nonce));

	/* All good */
	return client_auth;
}

int pankake_server_authorize(
	const unsigned char *key_agreed,
	const unsigned char *client_auth,
	const unsigned char *pwhash,
	const unsigned char *salt,
	size_t salt_len)
{
	int rounds = 5000;
	unsigned char pwhash_c[HASH_DIGEST_SIZE_SHA512];
	unsigned char nonce[CRYPT_NONCE_SIZE_XSALSA20];
	unsigned char pw_payload[256 + 1];
	unsigned char *password = &pw_payload[1];
	size_t out_len = 0, pw_len = 0;

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
	if (memcmp(pwhash, pwhash_c, HASH_DIGEST_SIZE_SHA512))
		return -1;

	/* Cleanup */
	memset(pwhash_c, 0, sizeof(pwhash_c));
	memset(nonce, 0, sizeof(nonce));
	memset(pw_payload, 0, sizeof(pw_payload));

	/* All good */
	return 0;
}

