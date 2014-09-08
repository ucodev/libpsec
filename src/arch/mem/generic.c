/*
 * @file generic.c
 * @brief PSEC Library
 *        Architecture Specific portable [MEMORY] interface 
 *
 * Date: 08-09-2014
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

#include <string.h>
#include <stdint.h>

#include "tc.h"

static inline int _is_little(void) {
	uint16_t u = 1;
	unsigned char v[2];

	tc_memcpy(v, &u, 2);

	return v[0];
}

/* Vector to uint */
static inline void _mem_copy_v2uint_fwd(void *uintf, const unsigned char *v, size_t len) {
	tc_memcpy(uintf, v, len);
}

static inline void _mem_copy_v2uint_rev(void *uintr, const unsigned char *v, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_tmp[len];

	for (i = 0; i < len; i ++)
		uintr_tmp[i ^ (len - 1)] = v[i];

	tc_memcpy(uintr, uintr_tmp, len);
}

uint16_t mem_copy_vect2word_little(uint16_t *word, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(word, v, 2);
	} else {
		_mem_copy_v2uint_rev(word, v, 2);
	}

	return *word;
}

uint16_t mem_copy_vect2word_big(uint16_t *word, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(word, v, 2);
	} else {
		_mem_copy_v2uint_fwd(word, v, 2);
	}

	return *word;
}

uint32_t mem_copy_vect2dword_little(uint32_t *dword, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(dword, v, 4);
	} else {
		_mem_copy_v2uint_rev(dword, v, 4);
	}

	return *dword;
}

uint32_t mem_copy_vect2dword_big(uint32_t *dword, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(dword, v, 4);
	} else {
		_mem_copy_v2uint_fwd(dword, v, 4);
	}

	return *dword;
}

uint64_t mem_copy_vect2qword_little(uint64_t *qword, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(qword, v, 8);
	} else {
		_mem_copy_v2uint_rev(qword, v, 8);
	}

	return *qword;
}

uint64_t mem_copy_vect2qword_big(uint64_t *qword, const unsigned char *v) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(qword, v, 8);
	} else {
		_mem_copy_v2uint_fwd(qword, v, 8);
	}

	return *qword;
}

/* uint to vector */
static inline void _mem_copy_uint2vect_fwd(unsigned char *v, const void *uintf, size_t len) {
	tc_memcpy(v, uintf, len);
}

static inline void _mem_copy_uint2vect_rev(unsigned char *v, const void *uintr, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_tmp[len];

	tc_memcpy(uintr_tmp, uintr, len);

	for (i = 0; i < len; i ++)
		v[i ^ (len - 1)] = uintr_tmp[i];
}

unsigned char *mem_copy_word2vect_little(unsigned char *v, const uint16_t word) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(v, &word, 2);
	} else {
		_mem_copy_uint2vect_rev(v, &word, 2);
	}

	return v;
}

unsigned char *mem_copy_word2vect_big(unsigned char *v, const uint16_t word) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(v, &word, 2);
	} else {
		_mem_copy_uint2vect_fwd(v, &word, 2);
	}

	return v;
}

unsigned char *mem_copy_dword2vect_little(unsigned char *v, const uint32_t dword) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(v, &dword, 4);
	} else {
		_mem_copy_uint2vect_rev(v, &dword, 4);
	}

	return v;
}

unsigned char *mem_copy_dword2vect_big(unsigned char *v, const uint32_t dword) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(v, &dword, 4);
	} else {
		_mem_copy_uint2vect_fwd(v, &dword, 4);
	}

	return v;
}

unsigned char *mem_copy_qword2vect_little(unsigned char *v, const uint64_t qword) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(v, &qword, 8);
	} else {
		_mem_copy_uint2vect_rev(v, &qword, 8);
	}

	return v;
}

unsigned char *mem_copy_qword2vect_big(unsigned char *v, const uint64_t qword) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(v, &qword, 8);
	} else {
		_mem_copy_uint2vect_fwd(v, &qword, 8);
	}

	return v;
}

/* uint to uint */
static inline void _mem_copy_uint2uint_fwd(void *uintf_d, const void *uintf_s, size_t len) {
	tc_memcpy(uintf_d, uintf_s, len);
}

static inline void _mem_copy_uint2uint_rev(void *uintr_d, const void *uintr_s, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_s_tmp[len];
	unsigned char uintr_d_tmp[len];

	tc_memcpy(uintr_s_tmp, uintr_s, len);
	
	for (i = 0; i < len; i ++)
		uintr_d_tmp[i ^ (len - 1)] = uintr_s_tmp[i];

	tc_memcpy(uintr_d, uintr_d_tmp, len);
}

uint16_t mem_copy_word2word_little(uint16_t *word_d, const uint16_t word_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(word_d, &word_s, 2);
	} else {
		_mem_copy_uint2uint_rev(word_d, &word_s, 2);
	}

	return *word_d;
}

uint16_t mem_copy_word2word_big(uint16_t *word_d, const uint16_t word_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(word_d, &word_s, 2);
	} else {
		_mem_copy_uint2uint_fwd(word_d, &word_s, 2);
	}

	return *word_d;
}

uint32_t mem_copy_dword2dword_little(uint32_t *dword_d, const uint32_t dword_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(dword_d, &dword_s, 4);
	} else {
		_mem_copy_uint2uint_rev(dword_d, &dword_s, 4);
	}

	return *dword_d;
}

uint32_t mem_copy_dword2dword_big(uint32_t *dword_d, const uint32_t dword_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(dword_d, &dword_s, 4);
	} else {
		_mem_copy_uint2uint_fwd(dword_d, &dword_s, 4);
	}

	return *dword_d;
}

uint64_t mem_copy_qword2qword_little(uint64_t *qword_d, const uint64_t qword_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(qword_d, &qword_s, 8);
	} else {
		_mem_copy_uint2uint_rev(qword_d, &qword_s, 8);
	}

	return *qword_d;
}

uint64_t mem_copy_qword2qword_big(uint64_t *qword_d, const uint64_t qword_s) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(qword_d, &qword_s, 8);
	} else {
		_mem_copy_uint2uint_fwd(qword_d, &qword_s, 8);
	}

	return *qword_d;
}

