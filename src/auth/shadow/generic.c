/*
 * @file generic.c
 * @brief PSEC Library
 *        Authentication [shadow] interface 
 *
 * Date: 01-09-2014
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
#include <shadow.h>

#include "../../../include/tc.h"

#ifdef _XOPEN_SOURCE
#include <unistd.h>
#endif

#ifdef _GNU_SOURCE
#include <crypt.h>
#endif

#ifndef _GNU_SOURCE
/* Use static mutexes for systems not supporting reentrant versions of the API */
#define _REENTRANT
#include <pthread.h>

static pthread_mutex_t _auth_shadow_mutex = PTHREAD_MUTEX_INITIALIZER;

#endif

int shadow_user_pass_verify(const char *username, const char *password) {
	int errsv = 0;
	struct spwd *spentp = NULL;
	size_t salt_len = 0;
	char *salt = NULL, *local_hash = NULL, *user_hash = NULL;
#ifdef _GNU_SOURCE
	char sp_buf[8192];
	struct spwd spent;
	struct crypt_data cd;
#endif

	/* Pre-check */
	if (!username || !password) {
		errno = EINVAL;
		return -1;
	}

#if defined(_GNU_SOURCE)
	/* GNU implementations support native reentrant functions */
	if (getspnam_r(username, &spent, sp_buf, sizeof(sp_buf), &spentp) < 0)
		return -1;
#else
	pthread_mutex_lock(&_auth_shadow_mutex);

	spentp = getspnam(username);

	errsv = errno;

	pthread_mutex_unlock(&_auth_shadow_mutex);
#endif

	/* Validate that spentp is valid */
	if (!spentp) {
		errno = errsv;
		return -1;
	}

	/* Search for '$' in the local hash. If found, extensions (non-POSIX) are enabled */
	if (!(local_hash = strrchr(spentp->sp_pwdp, '$'))) {
		/* DES (default) */
		if (strlen(spentp->sp_pwdp) <= 2) {
			errno = ENOSYS;
			return -1;
		}

		salt_len = 2;
	} else {
		/* Extensions */
		local_hash ++;
		salt_len = local_hash - spentp->sp_pwdp;
	}

	/* Allocate memory for salt */
	if (!(salt = malloc(salt_len + 1)))
		return -1;

	/* Isolate salt */
	memcpy(salt, spentp->sp_pwdp, salt_len);
	salt[salt_len] = 0;

#ifdef _GNU_SOURCE
	/* cd.initialized = 0; */
	tc_memset(&cd, 0, sizeof(struct crypt_data));

	/* Generate password hash */
	if (!(user_hash = crypt_r(password, salt, &cd))) {
		errsv = errno;
		free(salt);
		errno = errsv;
		return -1;
	}

#else
	pthread_mutex_lock(&_auth_shadow_mutex);

	/* Generate password hash (non-reentrant) */
	if (!(user_hash = crypt(password, salt))) {
		errsv = errno;
		free(salt);
		errno = errsv;
		return -1;
	}

	pthread_mutex_unlock(&_auth_shadow_mutex);
#endif

	/* Free unused memory */
	free(salt);

	/* Compare hashes */
	if (strcmp(spentp->sp_pwdp, user_hash)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

