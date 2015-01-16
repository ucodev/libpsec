/*
 * @file generic.c
 * @brief PSEC Library
 *        Encoding interface 
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

#include <stdio.h>
#include <stdlib.h>

#include "config.h"

#include "encode/base16/generic.h"
#include "encode/base64/generic.h"

#include "encode.h"

/* Base16 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *encode_buffer_base16(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	return base16_encode(out, out_len, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
size_t encode_size_base16(size_t in_len) {
	return base16_encode_size(in_len);
}

/* Base64 Interface */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
unsigned char *encode_buffer_base64(unsigned char *out, size_t *out_len, const unsigned char *in, size_t in_len) {
	return base64_encode(out, out_len, in, in_len);
}

#ifdef COMPILE_WIN32
DLLIMPORT
#endif
size_t encode_size_base64(size_t in_len) {
	return base64_encode_size(in_len);
}

/* Generic */
#ifdef COMPILE_WIN32
DLLIMPORT
#endif
void encode_destroy(unsigned char *encode) {
	free(encode);
}

