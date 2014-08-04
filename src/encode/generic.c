/*
 * @file generic.c
 * @brief PSEC Library
 *        Encoding interface 
 *
 * Date: 03-08-2014
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

#include <stdio.h>
#include <stdlib.h>

#include "encode/base64/generic.h"

#include "encode.h"

/* MD Interface */
char *encode_buffer_base64(char *out, size_t *out_len, const char *in, size_t len) {
	return base64_encode(out, out_len, in, len);
}

/* Generic */
void encode_destroy(char *encode) {
	free(encode);
}

