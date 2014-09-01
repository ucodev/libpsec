/*
 * @file generic.h
 * @brief PSEC Library
 *        Time Constant [Memory Operations] interface header
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

#ifndef LIBPSEC_GENERIC_TC_MEM_H
#define LIBPSEC_GENERIC_TC_MEM_H

#include <stdio.h>


/* Prototypes */
int memcmp_timec(const void *s1, const void *s2, size_t n);
void *memcpy_timec(void *dest, const void *src, size_t n);
void *memmove_timec(void *dest, const void *src, size_t n);
void *memset_timec(void *s, int c, size_t n);

#endif

