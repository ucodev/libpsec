/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [BLAKE] low level interface header
 *
 * Date: 04-09-2014
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

#ifndef LIBPSEC_BLAKE_LOW_H
#define LIBPSEC_BLAKE_LOW_H

#include <stdio.h>

#include "blake.h"

/* BLAKE-224 Low Level Interface */
int blake224_low_init(state224 *context);
int blake224_low_update(state224 *context, const unsigned char *in, size_t in_len);
int blake224_low_final(state224 *context, unsigned char *out);
/* BLAKE-256 Low Level Interface */
int blake256_low_init(state256 *context);
int blake256_low_update(state256 *context, const unsigned char *in, size_t in_len);
int blake256_low_final(state256 *context, unsigned char *out);
/* BLAKE-384 Low Level Interface */
int blake384_low_init(state384 *context);
int blake384_low_update(state384 *context, const unsigned char *in, size_t in_len);
int blake384_low_final(state384 *context, unsigned char *out);
/* BLAKE-512 Low Level Interface */
int blake512_low_init(state512 *context);
int blake512_low_update(state512 *context, const unsigned char *in, size_t in_len);
int blake512_low_final(state512 *context, unsigned char *out);

#endif

