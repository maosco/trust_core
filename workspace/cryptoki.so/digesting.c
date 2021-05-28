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
#include <string.h>

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_USER_TYPE g_loggedInUser;
extern CK_BYTE g_SessionIsOpen[];

#define COMMON_CHECKS() \
	if(!g_bInitialised) \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	if(!g_bDeviceOK) \
		return CKR_DEVICE_REMOVED; \
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(!g_SessionIsOpen[hSession]) \
		return CKR_SESSION_HANDLE_INVALID;

// Locals
static BYTE bOperationInProgress = 0;
static BYTE bOneShotAllowed = 0;

/* C_DigestInit initializes a message-digesting operation. */
CK_RV C_DigestInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	BYTE bHashLen = 20; //SHA-1

	logFunc(__func__);

	COMMON_CHECKS();

	if(pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// Mentioned in the specification but not required for C_Digest itself
	//if(g_loggedInUser == NO_LOGGED_IN_USER)
	//	return CKR_USER_NOT_LOGGED_IN;

	if(pMechanism->mechanism == CKM_SHA_1)
		bHashLen = 20;
	else if (pMechanism->mechanism == CKM_SHA256)
		bHashLen = 32;
	else if (pMechanism->mechanism == CKM_SHA384)
		bHashLen = 48;
	else if (pMechanism->mechanism == CKM_SHA512)
		bHashLen = 64;
	else
		return CKR_MECHANISM_INVALID;

	if(!tcShaInit(bHashLen))
		return CKR_FUNCTION_FAILED;

	bOperationInProgress = 1;
	bOneShotAllowed = 1;
	return CKR_OK;
}


/* C_Digest digests data in a single part. */
CK_RV C_Digest
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	BYTE wNumBlocks;
	BYTE bNumRemain;
	WORD i;

	logFunc(__func__);

	COMMON_CHECKS();

	if(pData == NULL_PTR || pDigest == NULL_PTR || pulDigestLen == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if(!bOneShotAllowed)
		return CKR_OPERATION_NOT_INITIALIZED;
	bOneShotAllowed = 0;

	wNumBlocks = ulDataLen / 255;
	bNumRemain = ulDataLen % 255;

	for(i = 0; i < wNumBlocks; i++)
		if(!tcShaUpdate(pData+(i*255),255))
			return CKR_FUNCTION_FAILED;
	tcShaUpdate(pData+(i*255),bNumRemain);

	*pulDigestLen = tcShaFinal(pDigest);
	if(*pulDigestLen == 0)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}


/* C_DigestUpdate continues a multiple-part message-digesting
 * operation. */
CK_RV C_DigestUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	logFunc(__func__);

	COMMON_CHECKS();

	if(!bOperationInProgress)
		return CKR_OPERATION_NOT_INITIALIZED;
	bOneShotAllowed = 0;

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_RV C_DigestKey
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	logFunc(__func__);

	COMMON_CHECKS();

	if(!bOperationInProgress)
		return CKR_OPERATION_NOT_INITIALIZED;
	bOperationInProgress = 0;
	bOneShotAllowed = 0;
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. */
CK_RV C_DigestFinal
(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	logFunc(__func__);

	COMMON_CHECKS();

	if(!bOperationInProgress)
		return CKR_OPERATION_NOT_INITIALIZED;
	bOperationInProgress = 0;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
