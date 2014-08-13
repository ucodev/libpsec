/*
 * @file generate.h
 * @brief PSEC Library
 *        Generate interface header
 *
 * Date: 13-08-2014
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

#ifndef LIBPSEC_GENERATE_H
#define LIBPSEC_GENERATE_H

#include <stdio.h>

/* Prototypes */
/********************/
/* Random Interface */
/********************/
unsigned char *generate_bytes_random(unsigned char *out, size_t len);
unsigned char *generate_dict_random(unsigned char *out, size_t out_len, unsigned char *dict, size_t dict_len);
/********************/
/* Common Interface */
/********************/
void generate_destroy(unsigned char *bytes);

#endif
