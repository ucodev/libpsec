/*
 * @file tc.h
 * @brief PSEC Library
 *        Time Constant interface header
 *
 * Date: 16-01-2015
 *
 * Copyright 2014-2015 Pedro A. Hortas (pah@ucodev.org)
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

#ifndef LIBPSEC_TC_H
#define LIBPSEC_TC_H

#include <stdio.h>

#include "config.h"

/* Prototypes */
/*********************/
/* Memory Operations */
/*********************/
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
int tc_memcmp(const void *s1, const void *s2, size_t n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void *tc_memcpy(void *dest, const void *src, size_t n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void *tc_memmove(void *dest, const void *src, size_t n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void *tc_memset(void *s, int c, size_t n);
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void *tc_memxor(void *dest, const void *src, size_t n);

#endif
