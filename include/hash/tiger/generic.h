/*
 * @file generic.h
 * @brief PSEC Library
 *        HASH [TIGER] generic interface header
 *
 * Date: 06-09-2014
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

#ifndef LIBPSEC_GENERIC_TIGER_H
#define LIBPSEC_GENERIC_TIGER_H

#include <stdio.h>


/* Definitions */
#define TIGER_HASH_DIGEST_SIZE		24
#define TIGER2_HASH_DIGEST_SIZE		24
#define TIGER_HASH_BLOCK_SIZE		64
#define TIGER2_HASH_BLOCK_SIZE		64

/* Prototypes */

/* TIGER Generic Interface */
unsigned char *tiger_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *tiger_file(unsigned char *out, FILE *fp);
/* TIGER2 Generic Interface */
unsigned char *tiger2_buffer(unsigned char *out, const unsigned char *in, size_t in_len);
unsigned char *tiger2_file(unsigned char *out, FILE *fp);


#endif

