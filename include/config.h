/*
 * @file config.h
 * @brief PSEC Library
 *        Configuration header
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

#ifndef LIBPSEC_CONFIG_H
#define LIBPSEC_CONFIG_H

#if defined(WIN32) || defined(_WIN32) || defined(WIN64) || defined(_WIN64)
 #include <windows.h>

 #ifndef COMPILE_WIN32
  #define COMPILE_WIN32
 #endif
 #if BUILDING_DLL
  #define DLLIMPORT __declspec(dllexport)
 #else
  #define DLLIMPORT __declspec(dllimport)
 #endif
#endif

#endif

