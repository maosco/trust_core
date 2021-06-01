/*
 * Copyright (c) 2020-2021, MULTOS Ltd
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions
 * and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 * and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

#ifndef COMMON_DEFS_H_
#define COMMON_DEFS_H_

#ifdef _WIN32
#define __func__ __FUNCTION__
#define gettid GetCurrentThreadId
#define getppid GetCurrentProcess
#else
#include <unistd.h>
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

#define LIB_MANUFACTURER_ID 	"MULTOS Ltd"
#ifdef _WIN32
#define LIB_DESC				"multos-cryptoki.dll"
#else
#define LIB_DESC        		"libmultos-cryptoki.so"
#endif
#define LIBRARY_MAJOR_VERSION	1
#define LIBRARY_MINOR_VERSION 	0

#define SLOT_MANUFACTURER_ID 	"MULTOS Ltd"

#define TOKEN_MANUFACTURER_ID 	"MULTOS Ltd"
#define TOKEN_MODEL_ID			"Trust Core"

#define CRYPTOKI_MINOR_VERSION 40

#define NO_LOGGED_IN_USER	99
#define MAX_SESSIONS		16
#define SESSION_STATE_KEYMAN	5UL

#define RSA_PUBLIC_KEY_SESSION_OBJECT	0x60FF
#define EC_PUBLIC_KEY_SESSION_OBJECT	0x60FE


extern void logFunc(const char * fn);
extern void padWithSpaces(char *buff, int len);

#endif /* COMMON_DEFS_H_ */
