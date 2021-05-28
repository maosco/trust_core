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

#include "pkcs11.h"
#include "tc_api.h"
#include "common_defs.h"
#include <stdio.h>

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_BYTE g_SessionIsOpen[];

#define COMMON_CHECKS() \
	if(!g_bInitialised) \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	if(!g_bDeviceOK) \
		return CKR_DEVICE_REMOVED;\
	if(hSession == 0 || hSession >= MAX_SESSIONS)\
		return CKR_SESSION_HANDLE_INVALID;\
	if(!g_SessionIsOpen[hSession])\
		return CKR_SESSION_HANDLE_INVALID;

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator. */
CK_RV C_SeedRandom
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pSeed,     /* the seed material */
  CK_ULONG          ulSeedLen  /* length of seed material */
)
{
	logFunc(__func__);

	COMMON_CHECKS();

	if(pSeed == NULL)
		return CKR_ARGUMENTS_BAD;

	// The seed is ignored as it is not needed by MULTOS
	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}


/* C_GenerateRandom generates random data. */
CK_RV C_GenerateRandom
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_BYTE_PTR       RandomData,  /* receives the random data */
  CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
	int blocks = 0;
	int remainder = 0;
	int i;
	int ok = 1;

	logFunc(__func__);

	COMMON_CHECKS();

	if(RandomData == NULL)
		return CKR_ARGUMENTS_BAD;

	// Maximum number of bytes per call is 256 bytes
	blocks = ulRandomLen / 256;
	remainder = ulRandomLen % 256;

	// Do all whole blocks first. Note a length of 0 actually means 256
	for(i = 0; i < blocks && ok; i++)
		ok = tcAskRandom(0,RandomData+(256*i));
	if(ok && remainder)
		ok = tcAskRandom(remainder,RandomData+(256*i));

	if(!ok)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

