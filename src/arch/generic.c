/*
 * @file generic.c
 * @brief PSEC Library
 *        Architecture Specific portable interface 
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

#include <stdint.h>

#include "arch/mem/generic.h"
#include "arch/spec/generic.h"

/*****************/
/* MEM Interface */
/*****************/
/* Vector to uint */
uint16_t arch_mem_copy_vect2word_little(uint16_t *word, const unsigned char *v) {
	return mem_copy_vect2word_little(word, v);
}

uint16_t arch_mem_copy_vect2word_big(uint16_t *word, const unsigned char *v) {
	return mem_copy_vect2word_big(word, v);
}

uint32_t arch_mem_copy_vect2dword_little(uint32_t *dword, const unsigned char *v) {
	return mem_copy_vect2dword_little(dword, v);
}

uint32_t arch_mem_copy_vect2dword_big(uint32_t *dword, const unsigned char *v) {
	return mem_copy_vect2dword_big(dword, v);
}

uint64_t arch_mem_copy_vect2qword_little(uint64_t *qword, const unsigned char *v) {
	return mem_copy_vect2qword_little(qword, v);
}

uint64_t arch_mem_copy_vect2qword_big(uint64_t *qword, const unsigned char *v) {
	return mem_copy_vect2qword_big(qword, v);
}

/* uint to vector */
unsigned char *arch_mem_copy_word2vect_little(unsigned char *v, const uint16_t word) {
	return mem_copy_word2vect_little(v, word);
}

unsigned char *arch_mem_copy_word2vect_big(unsigned char *v, const uint16_t word) {
	return mem_copy_word2vect_big(v, word);
}

unsigned char *arch_mem_copy_dword2vect_little(unsigned char *v, const uint32_t dword) {
	return mem_copy_dword2vect_little(v, dword);
}

unsigned char *arch_mem_copy_dword2vect_big(unsigned char *v, const uint32_t dword) {
	return mem_copy_dword2vect_big(v, dword);
}

unsigned char *arch_mem_copy_qword2vect_little(unsigned char *v, const uint64_t qword) {
	return mem_copy_qword2vect_little(v, qword);
}

unsigned char *arch_mem_copy_qword2vect_big(unsigned char *v, const uint64_t qword) {
	return mem_copy_qword2vect_big(v, qword);
}

/* uint to uint */
uint16_t arch_mem_copy_word2word_little(uint16_t *word_d, const uint16_t word_s) {
	return mem_copy_word2word_little(word_d, word_s);
}

uint16_t arch_mem_copy_word2word_big(uint16_t *word_d, const uint16_t word_s) {
	return mem_copy_word2word_big(word_d, word_s);
}

uint32_t arch_mem_copy_dword2dword_little(uint32_t *dword_d, const uint32_t dword_s) {
	return mem_copy_dword2dword_little(dword_d, dword_s);
}

uint32_t arch_mem_copy_dword2dword_big(uint32_t *dword_d, const uint32_t dword_s) {
	return mem_copy_dword2dword_big(dword_d, dword_s);
}

uint64_t arch_mem_copy_qword2qword_little(uint64_t *qword_d, const uint64_t qword_s) {
	return mem_copy_qword2qword_little(qword_d, qword_s);
}

uint64_t arch_mem_copy_qword2qword_big(uint64_t *qword_d, const uint64_t qword_s) {
	return mem_copy_qword2qword_big(qword_d, qword_s);
}

/******************/
/* SPEC Interface */
/******************/
int arch_spec_endianness_is_little(void) {
	return spec_endianness_is_little();
}

int arch_spec_endianness_is_big(void) {
	return spec_endianness_is_big();
}

