/*
 * @file generic.c
 * @brief PSEC Library
 *        Generate [Random] generic interface header
 *
 * Date: 08-08-2014
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
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

unsigned char *random_bytes(unsigned char *out, size_t len) {
	int i = 0, errsv = 0;
	FILE *fp = NULL;
	struct timespec tp;
	unsigned int clk = 0;
	int out_alloc = 0;

	if (!out) {
		if (!(out = malloc(len)))
			return NULL;

		out_alloc = 1;
	}

	if ((fp = fopen("/dev/urandom", "r"))) {
		if (fread(out, len, 1, fp) != 1) {
			errsv = errno;
			fclose(fp);
			if (out_alloc) free(out);
			errno = errsv;
			return NULL;
		}

		fclose(fp);
	} else if ((fp = fopen("/dev/random", "r"))) {
		if (fread(out, len, 1, fp) != 1) {
			errsv = errno;
			fclose(fp);
			if (out_alloc) free(out);
			errno = errsv;
			return NULL;
		}

		fclose(fp);
	} else {
		/* Weak alternative */
		if (clock_gettime(CLOCK_REALTIME, &tp) < 0) {
			errsv = errno;
			if (out_alloc) free(out);
			errno = errsv;
			return NULL;
		}

		if (!tp.tv_sec)
			tp.tv_sec = 3;

		if (!tp.tv_nsec)
			tp.tv_nsec = 5;

		if (!(clk = (unsigned int) clock()))
			clk = 7;

		srandom(tp.tv_sec * tp.tv_sec * clk * (getpid() + 11) * (getppid() + 13) * (getuid() + 17) * (getgid() + 19));

		for (i = 0; i < len; i += ((len - i) < sizeof(unsigned int)) ? (len - i) : sizeof(unsigned int)) {
			memcpy(out + i, (unsigned int [1]) { (random() + 31) * (random() + 47) + (random() + 57) * (random() + 111) }, ((len - i) < sizeof(unsigned int)) ? (len - i) : sizeof(unsigned int));
		}
	}

	return out;
}

