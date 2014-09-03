/*
 * @file generic.c
 * @brief PSEC Library
 *        Encrypted Key Exhange [DH EKE] interface 
 *
 * Date: 03-09-2014
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

#include "crypt.h"
#include "hash.h"
#include "kdf.h"
#include "ke.h"
#include "mac.h"
#include "tc.h"

#include "ke/dheke/generic.h"


static void _dheke_context_destroy(unsigned char *context) {
	struct dheke_context *ctx = (struct dheke_context *) context;

	if (ctx->c_pub && ctx->c_prv)  ke_destroy(ctx->c_pub);
	if (ctx->c_pub && !ctx->c_prv) crypt_destroy(ctx->c_pub);
	if (ctx->s_pub && ctx->s_prv)  ke_destroy(ctx->s_pub);
	if (ctx->s_pub && !ctx->s_prv) crypt_destroy(ctx->s_pub);

	if (ctx->pwd)    free(ctx->pwd);
	if (ctx->salt)   free(ctx->salt);
	if (ctx->pwhash) kdf_destroy(ctx->pwhash);
	if (ctx->c_prv)  ke_destroy(ctx->c_prv);
	if (ctx->s_prv)  ke_destroy(ctx->s_prv);
	if (ctx->shr)    ke_destroy(ctx->shr);

	tc_memset(ctx, 0, sizeof(struct dheke_context));
}

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
	unsigned int use_mac)
{
	int errsv = 0;
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	struct dheke_context *ctx = (struct dheke_context *) context;
	size_t out_len = 0;

	/* Clear context memory */
	tc_memset(ctx, 0, sizeof(struct dheke_context));

	/* Set context data */
	ctx->pub_len = pub_len;
	ctx->prv_len = prv_len;
	ctx->pwd_len = pwd_len;
	ctx->salt_len = salt_len;
	ctx->pwhash_len = use_mac ? CRYPT_KEY_SIZE_CHACHA20 : pub_len;
	ctx->use_mac = use_mac;

	if (!(ctx->pwd = malloc(ctx->pwd_len)))
		return NULL;

	if (!(ctx->salt = malloc(ctx->salt_len)))
		return NULL;

	tc_memcpy(ctx->pwd, pwd, ctx->pwd_len);
	tc_memcpy(ctx->salt, salt, ctx->salt_len);

	/* Create DH private key */
	if (!(ctx->c_prv = ke_dh_private(NULL, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Create DH public key */
	if (!(ctx->c_pub = ke_dh_public(NULL, ctx->pub_len, ctx->c_prv, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Create a password hash matching the size of the public key */
	if (!(ctx->pwhash = kdf_pbkdf2_hash(NULL, mac_hmac_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, pwd, pwd_len, salt, salt_len, pbkdf2_rounds, ctx->pwhash_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Check if MAC is required */
	if (ctx->use_mac) {
		tc_memset(nonce, 255, sizeof(nonce));
		nonce[sizeof(nonce) - 1] = 254;

		/* ChaCha20 encryption with Poly1305 message authentication code */
		if (!(client_session = crypt_encrypt_chacha20poly1305(client_session, &out_len, ctx->c_pub, ctx->pub_len, nonce, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	} else {
		/* OTP encryption, no message authentication code */
		if (!(client_session = crypt_encrypt_otp(client_session, &out_len, ctx->c_pub, ctx->pub_len, NULL, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	}

	/* All good */
	return client_session;
}

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
	unsigned int use_mac)
{
	int errsv = 0;
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	struct dheke_context *ctx = (struct dheke_context *) context;
	size_t out_len = 0;

	/* Clear context memory */
	tc_memset(ctx, 0, sizeof(struct dheke_context));

	/* Set context data */
	ctx->pub_len = pub_len;
	ctx->prv_len = prv_len;
	ctx->pwd_len = pwd_len;
	ctx->salt_len = salt_len;
	ctx->pwhash_len = use_mac ? CRYPT_KEY_SIZE_CHACHA20 : pub_len;
	ctx->use_mac = use_mac;

	if (!(ctx->pwd = malloc(ctx->pwd_len)))
		return NULL;

	if (!(ctx->salt = malloc(ctx->salt_len)))
		return NULL;

	tc_memcpy(ctx->pwd, pwd, ctx->pwd_len);
	tc_memcpy(ctx->salt, salt, ctx->salt_len);

	/* Create a password hash matching the size of the public key */
	if (!(ctx->pwhash = kdf_pbkdf2_hash(NULL, mac_hmac_sha512, HASH_DIGEST_SIZE_SHA512, HASH_BLOCK_SIZE_SHA512, pwd, pwd_len, salt, salt_len, pbkdf2_rounds, ctx->pwhash_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Check if MAC is required */
	if (ctx->use_mac) {
		tc_memset(nonce, 255, sizeof(nonce));
		nonce[sizeof(nonce) - 1] = 254;

		/* ChaCha20 decryption with Poly1305 message authentication code */
		if (!(ctx->c_pub = crypt_decrypt_chacha20poly1305(NULL, &out_len, client_session, ctx->pub_len + CRYPT_EXTRA_SIZE_CHACHA20POLY1305, nonce, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	} else {
		/* OTP encryption, no message authentication code */
		if (!(ctx->c_pub = crypt_decrypt_otp(NULL, &out_len, client_session, ctx->pub_len, NULL, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	}

	/* Create DH private key */
	if (!(ctx->s_prv = ke_dh_private(NULL, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Create DH public key */
	if (!(ctx->s_pub = ke_dh_public(NULL, ctx->pub_len, ctx->s_prv, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Compute shared key */
	if (!(ctx->shr = ke_dh_shared(NULL, ctx->c_pub, ctx->pub_len, ctx->s_prv, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Copy key */
	tc_memcpy(key, ctx->shr, ctx->pub_len);

	/* Check if MAC is required */
	if (ctx->use_mac) {
		tc_memset(nonce, 255, sizeof(nonce));

		/* ChaCha20 encryption with Poly1305 message authentication code */
		if (!(server_session = crypt_encrypt_chacha20poly1305(server_session, &out_len, ctx->s_pub, ctx->pub_len, nonce, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	} else {
		/* OTP encryption, no message authentication code */
		if (!(server_session = crypt_encrypt_otp(server_session, &out_len, ctx->s_pub, ctx->pub_len, NULL, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	}

	/* Cleanup context */
	_dheke_context_destroy(context);

	/* All good */
	return server_session;
}

unsigned char *dheke_client_process(
	unsigned char *key,
	unsigned char *context,
	const unsigned char *server_session)
{
	int errsv = 0;
	unsigned char nonce[CRYPT_NONCE_SIZE_CHACHA20];
	struct dheke_context *ctx = (struct dheke_context *) context;
	size_t out_len = 0;

	/* Check if MAC is required */
	if (ctx->use_mac) {
		tc_memset(nonce, 255, sizeof(nonce));

		/* ChaCha20 decryption with Poly1305 message authentication code */
		if (!(ctx->s_pub = crypt_decrypt_chacha20poly1305(NULL, &out_len, server_session, ctx->pub_len + CRYPT_EXTRA_SIZE_CHACHA20POLY1305, nonce, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	} else {
		/* OTP encryption, no message authentication code */
		if (!(ctx->s_pub = crypt_decrypt_otp(NULL, &out_len, server_session, ctx->pub_len, NULL, ctx->pwhash))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	}

	/* Compute shared key */
	if (!(ctx->shr = ke_dh_shared(NULL, ctx->s_pub, ctx->pub_len, ctx->c_prv, ctx->prv_len))) {
		errsv = errno;
		_dheke_context_destroy(context);
		errno = errsv;
		return NULL;
	}

	/* Allocate key if required */
	if (!key) {
		if (!(key = malloc(ctx->pub_len))) {
			errsv = errno;
			_dheke_context_destroy(context);
			errno = errsv;
			return NULL;
		}
	}

	/* Copy key */
	tc_memcpy(key, ctx->shr, ctx->pub_len);

	/* Destroy context */
	_dheke_context_destroy(context);

	/* All good */
	return key;
}

