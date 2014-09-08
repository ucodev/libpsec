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

static inline int _is_little(void) {
	uint16_t u = 1;
	unsigned char v[2];

	memcpy(v, &u, 2);

	return v[0];
}

/* Vector to uint */
static inline void _mem_copy_v2uint_fwd(const unsigned char *v, void *uintf, size_t len) {
	memcpy(uintf, v, len);
}

static inline void _mem_copy_v2uint_rev(const unsigned char *v, void *uintr, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_tmp[len];

	for (i = 0; i < len; i ++)
		uintr_tmp[i ^ (len - 1)] = v[i];

	memcpy(uintr, uintr_tmp, len);
}

void mem_copy_vect2word_little(const unsigned char *v, uint16_t *word) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(v, word, 2);
	} else {
		_mem_copy_v2uint_rev(v, word, 2);
	}
}

void mem_copy_vect2word_big(const unsigned char *v, uint16_t *word) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(v, word, 2);
	} else {
		_mem_copy_v2uint_fwd(v, word, 2);
	}
}

void mem_copy_vect2dword_little(const unsigned char *v, uint32_t *dword) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(v, dword, 4);
	} else {
		_mem_copy_v2uint_rev(v, dword, 4);
	}
}

void mem_copy_vect2dword_big(const unsigned char *v, uint32_t *dword) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(v, dword, 4);
	} else {
		_mem_copy_v2uint_fwd(v, dword, 4);
	}
}

void mem_copy_vect2qword_little(const unsigned char *v, uint64_t *qword) {
	if (_is_little()) {
		_mem_copy_v2uint_fwd(v, qword, 8);
	} else {
		_mem_copy_v2uint_rev(v, qword, 8);
	}
}

void mem_copy_vect2qword_big(const unsigned char *v, uint64_t *qword) {
	if (_is_little()) {
		_mem_copy_v2uint_rev(v, qword, 8);
	} else {
		_mem_copy_v2uint_fwd(v, qword, 8);
	}
}

/* uint to vector */
static inline void _mem_copy_uint2vect_fwd(const void *uintf, unsigned char *v, size_t len) {
	memcpy(v, uintf, len);
}

static inline void _mem_copy_uint2vect_rev(const void *uintr, unsigned char *v, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_tmp[len];

	memcpy(uintr_tmp, uintr, len);

	for (i = 0; i < len; i ++)
		v[i ^ (len - 1)] = uintr_tmp[i];
}

void mem_copy_word2vect_little(const uint16_t *word, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(word, v, 2);
	} else {
		_mem_copy_uint2vect_rev(word, v, 2);
	}
}

void mem_copy_word2vect_big(const uint16_t *word, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(word, v, 2);
	} else {
		_mem_copy_uint2vect_fwd(word, v, 2);
	}
}

void mem_copy_dword2vect_little(const uint32_t *dword, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(dword, v, 4);
	} else {
		_mem_copy_uint2vect_rev(dword, v, 4);
	}
}

void mem_copy_dword2vect_big(const uint32_t *dword, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(dword, v, 4);
	} else {
		_mem_copy_uint2vect_fwd(dword, v, 4);
	}
}

void mem_copy_qword2vect_little(const uint64_t *qword, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_fwd(qword, v, 8);
	} else {
		_mem_copy_uint2vect_rev(qword, v, 8);
	}
}

void mem_copy_qword2vect_big(const uint64_t *qword, unsigned char *v) {
	if (_is_little()) {
		_mem_copy_uint2vect_rev(qword, v, 8);
	} else {
		_mem_copy_uint2vect_fwd(qword, v, 8);
	}
}

/* uint to uint */
static inline void _mem_copy_uint2uint_fwd(const void *uintf_s, void *uintf_d, size_t len) {
	memcpy(uintf_d, uintf_s, len);
}

static inline void _mem_copy_uint2uint_rev(const void *uintr_s, void *uintr_d, size_t len) {
	unsigned int i = 0;
	unsigned char uintr_s_tmp[len];
	unsigned char uintr_d_tmp[len];

	memcpy(uintr_s_tmp, uintr_s, len);
	
	for (i = 0; i < len; i ++)
		uintr_d_tmp[i ^ (len - 1)] = uintr_s_tmp[i];

	memcpy(uintr_d, uintr_d_tmp, len);
}

void mem_copy_word2word_little(const uint16_t *word_s, uint16_t *word_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(word_s, word_d, 2);
	} else {
		_mem_copy_uint2uint_rev(word_s, word_d, 2);
	}
}

void mem_copy_word2word_big(const uint16_t *word_s, uint16_t *word_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(word_s, word_d, 2);
	} else {
		_mem_copy_uint2uint_fwd(word_s, word_d, 2);
	}
}

void mem_copy_dword2dword_little(const uint32_t *dword_s, uint32_t *dword_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(dword_s, dword_d, 4);
	} else {
		_mem_copy_uint2uint_rev(dword_s, dword_d, 4);
	}
}

void mem_copy_dword2dword_big(const uint32_t *dword_s, uint32_t *dword_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(dword_s, dword_d, 4);
	} else {
		_mem_copy_uint2uint_fwd(dword_s, dword_d, 4);
	}
}

void mem_copy_qword2qword_little(const uint64_t *qword_s, uint64_t *qword_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_fwd(qword_s, qword_d, 8);
	} else {
		_mem_copy_uint2uint_rev(qword_s, qword_d, 8);
	}
}

void mem_copy_qword2qword_big(const uint64_t *qword_s, uint64_t *qword_d) {
	if (_is_little()) {
		_mem_copy_uint2uint_rev(qword_s, qword_d, 8);
	} else {
		_mem_copy_uint2uint_fwd(qword_s, qword_d, 8);
	}
}

