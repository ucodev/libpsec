/*
 * @file generic.h
 * @brief PSEC Library
 *        Base16 decoding interface header
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

#ifndef LIBPSEC_GENERIC_DECODE_BASE16_H
#define LIBPSEC_GENERIC_DECODE_BASE16_H

#include <stdio.h>

/* Prototypes */
size_t base16_decode_size(size_t in_len);
unsigned char *base16_decode(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len);

#endif
