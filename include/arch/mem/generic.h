/*
 * @file generic.h
 * @brief PSEC Library
 *        Architecture Specific portable [MEMORY] interface header
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

#ifndef LIBPSEC_ARCH_GENERIC_MEM_H
#define LIBPSEC_ARCH_GENERIC_MEM_H

#include <stdint.h>

/* Vector to uint */
void mem_copy_vect2word_little(const unsigned char *v, uint16_t *word);
void mem_copy_vect2word_big(const unsigned char *v, uint16_t *word);
void mem_copy_vect2dword_little(const unsigned char *v, uint32_t *dword);
void mem_copy_vect2dword_big(const unsigned char *v, uint32_t *dword);
void mem_copy_vect2qword_little(const unsigned char *v, uint64_t *qword);
void mem_copy_vect2qword_big(const unsigned char *v, uint64_t *qword);

/* uint to vector */
void mem_copy_word2vect_little(const uint16_t *word, unsigned char *v);
void mem_copy_word2vect_big(const uint16_t *word, unsigned char *v);
void mem_copy_dword2vect_little(const uint32_t *dword, unsigned char *v);
void mem_copy_dword2vect_big(const uint32_t *dword, unsigned char *v);
void mem_copy_qword2vect_little(const uint64_t *qword, unsigned char *v);
void mem_copy_qword2vect_big(const uint64_t *qword, unsigned char *v);

#endif

