/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [Blake2] low level interface header
 *
 * Date: 04-08-2014
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

#ifndef LIBPSEC_BLAKE2_LOW_H
#define LIBPSEC_BLAKE2_LOW_H

#include <stdio.h>

#include "blake2.h"

/* Blake2b Low Level Interface */
int blake2b_low_init(blake2b_state *context);
int blake2b_low_update(blake2b_state *context, const char *in, size_t len);
int blake2b_low_final(blake2b_state *context, char *out);

/* Blake2s Low Level Interface */
int blake2s_low_init(blake2s_state *context);
int blake2s_low_update(blake2s_state *context, const char *in, size_t len);
int blake2s_low_final(blake2s_state *context, char *out);


#endif

