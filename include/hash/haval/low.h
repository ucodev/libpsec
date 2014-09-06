/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [HAVAL] low level interface header
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

#ifndef LIBPSEC_HAVAL_LOW_H
#define LIBPSEC_HAVAL_LOW_H

#include <stdio.h>

#include "haval.h"

/* HAVAL-256 Low Level Interface */
int haval256_low_init(haval_state *context);
int haval256_low_init_passes(haval_state *context, unsigned int passes);
int haval256_low_update(haval_state *context, const unsigned char *in, size_t in_len);
int haval256_low_final(haval_state *context, unsigned char *out);
/* HAVAL-224 Low Level Interface */
int haval224_low_init(haval_state *context);
int haval224_low_init_passes(haval_state *context, unsigned int passes);
int haval224_low_update(haval_state *context, const unsigned char *in, size_t in_len);
int haval224_low_final(haval_state *context, unsigned char *out);
/* HAVAL-192 Low Level Interface */
int haval192_low_init(haval_state *context);
int haval192_low_init_passes(haval_state *context, unsigned int passes);
int haval192_low_update(haval_state *context, const unsigned char *in, size_t in_len);
int haval192_low_final(haval_state *context, unsigned char *out);
/* HAVAL-160 Low Level Interface */
int haval160_low_init(haval_state *context);
int haval160_low_init_passes(haval_state *context, unsigned int passes);
int haval160_low_update(haval_state *context, const unsigned char *in, size_t in_len);
int haval160_low_final(haval_state *context, unsigned char *out);
/* HAVAL-128 Low Level Interface */
int haval128_low_init(haval_state *context);
int haval128_low_init_passes(haval_state *context, unsigned int passes);
int haval128_low_update(haval_state *context, const unsigned char *in, size_t in_len);
int haval128_low_final(haval_state *context, unsigned char *out);

#endif

