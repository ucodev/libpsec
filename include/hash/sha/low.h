/*
 * @file low.h
 * @brief PSEC Library
 *        HASH [SHA] low level interface header
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

#ifndef LIBPSEC_SHA_LOW_H
#define LIBPSEC_SHA_LOW_H

#include <stdio.h>

#include "sha.h"
#include "sha-private.h"

/* SHA1 Low Level Interface */
int sha1_low_init(SHA1Context *context);
int sha1_low_update(SHA1Context *context, const unsigned char *in, size_t in_len);
int sha1_low_final(SHA1Context *context, unsigned char *out);

/* SHA224 Low Level Interface */
int sha224_low_init(SHA224Context *context);
int sha224_low_update(SHA224Context *context, const unsigned char *in, size_t in_len);
int sha224_low_final(SHA224Context *context, unsigned char *out);

/* SHA256 Low Level Interface */
int sha256_low_init(SHA256Context *context);
int sha256_low_update(SHA256Context *context, const unsigned char *in, size_t in_len);
int sha256_low_final(SHA256Context *context, unsigned char *out);

/* SHA384 Low Level Interface */
int sha384_low_init(SHA384Context *context);
int sha384_low_update(SHA384Context *context, const unsigned char *in, size_t in_len);
int sha384_low_final(SHA384Context *context, unsigned char *out);

/* SHA512 Low Level Interface */
int sha512_low_init(SHA512Context *context);
int sha512_low_update(SHA512Context *context, const unsigned char *in, size_t in_len);
int sha512_low_final(SHA512Context *context, unsigned char *out);

#endif

