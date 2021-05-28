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

#include <string.h>
#include "pkcs11.h"
#include "tc_api.h"
#include "common_defs.h"

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_USER_TYPE g_loggedInUser;
extern CK_BYTE g_SessionIsOpen[];

#define COMMON_CHECKS() \
	if(!g_bInitialised) \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	if(!g_bDeviceOK) \
		return CKR_DEVICE_REMOVED;\
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(!g_SessionIsOpen[hSession]) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(g_loggedInUser == NO_LOGGED_IN_USER)\
		return CKR_USER_NOT_LOGGED_IN;

// Locals
static CK_BBOOL bInitialised = FALSE;
static CK_BYTE abIv[255];		// Maximum size for GCM is 256 but current implementation restricts to a single length byte. May need to be changed.
static CK_BYTE bIvLen = 0;
static CK_BYTE abAdd[255];
static CK_BYTE bAddLen = 0;
static CK_BBOOL bGcmMode = FALSE;

/* C_DecryptInit initializes a decryption operation. */
CK_RV C_DecryptInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	CK_GCM_PARAMS_PTR pGcmParams;

	logFunc(__func__);

	COMMON_CHECKS();

	bIvLen = 0;
	bAddLen = 0;
	bGcmMode = FALSE;

	switch(pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:
			// The key must be one of the two supported
			if(hKey != 0x6100 && hKey != 0x6101)
				return CKR_KEY_HANDLE_INVALID;

			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			// Set the algo in the template
			if(!tcMseSetAlgo(TC_ALGO_RSA,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			// Set the key to use
			if(!tcMseSetKeyFile(hKey,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_KEY_HANDLE_INVALID;

			break;

		case CKM_AES_CBC:
			// The key must be a secret key
			if((hKey & TC_EFTYPE_SECRET) != TC_EFTYPE_SECRET)
				return CKR_KEY_HANDLE_INVALID;

			// The mechanism parameter is the IV and must be supplied
			if(pMechanism->ulParameterLen != AES_BLOCK_LEN || pMechanism->pParameter == NULL_PTR)
				return CKR_MECHANISM_PARAM_INVALID;

			// Copy the IV to the cache
			memcpy(abIv,pMechanism->pParameter,AES_BLOCK_LEN);
			bIvLen = AES_BLOCK_LEN;

			// Set the algo in the template
			if(!tcMseSetAlgo(TC_ALGO_AES_CBC,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			// Set the key to use
			if(!tcMseSetKeyFile(hKey,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_KEY_HANDLE_INVALID;

			break;

		case CKM_AES_GCM:
			// The key must be a secret key
			if((hKey & TC_EFTYPE_SECRET) != TC_EFTYPE_SECRET)
				return CKR_KEY_HANDLE_INVALID;

			// There must be a mechanism parameter
			if(pMechanism->ulParameterLen != sizeof(CK_GCM_PARAMS) || pMechanism->pParameter == NULL_PTR)
				return CKR_MECHANISM_PARAM_INVALID;
			pGcmParams = (CK_GCM_PARAMS_PTR)pMechanism->pParameter;

			// There may be an IV specified
			if (pGcmParams->ulIvLen > 0)
			{
				if(!pGcmParams->pIv || pGcmParams->ulIvLen > sizeof(abIv))
					return CKR_MECHANISM_PARAM_INVALID;

				memcpy(abIv,pGcmParams->pIv,pGcmParams->ulIvLen);
				bIvLen = pGcmParams->ulIvLen;
			}
			else
				bIvLen = 0;

			// The tag length must be 128 bits (16 bytes).
			if(pGcmParams->ulTagBits != 128)
				return CKR_MECHANISM_PARAM_INVALID;

			// If additional data has been provided, cache it
			if(pGcmParams->ulAADLen > 255)
				return CKR_MECHANISM_PARAM_INVALID;
			if(pGcmParams->pAAD && pGcmParams->ulAADLen > 0)
			{
				memcpy(abAdd,pGcmParams->pAAD,pGcmParams->ulAADLen);
				bAddLen = pGcmParams->ulAADLen;
			}
			else
				bAddLen = 0;

			// Set the algo in the template
			if(!tcMseSetAlgo(TC_ALGO_AES_GCM,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			// Set the key to use
			if(!tcMseSetKeyFile(hKey,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_KEY_HANDLE_INVALID;

			bGcmMode = TRUE;
			break;

		default:
			return CKR_MECHANISM_INVALID;
			break;
	}
	bInitialised = TRUE;
	return CKR_OK;
}

/* C_Decrypt decrypts encrypted data in a single part. */
CK_RV C_Decrypt
(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	int status;

	logFunc(__func__);

	COMMON_CHECKS();

	if(bInitialised)
	{
		if(bGcmMode)
			status = tcDecryptGcm(pEncryptedData, (WORD) ulEncryptedDataLen, abIv, bIvLen, abAdd, bAddLen, pData, (WORD*) pulDataLen);
		else
			status = tcDecrypt(pEncryptedData, (WORD) ulEncryptedDataLen, abIv, bIvLen, pData, (WORD*) pulDataLen);

		if(status == 2)
			return CKR_BUFFER_TOO_SMALL;

		if(status == 0 && pData == 0)
			return CKR_OK;

		// Anything else and init is required again
		bInitialised = FALSE;

		if(status == 1)
			return CKR_ENCRYPTED_DATA_LEN_RANGE;

		if(status == 3)
			return CKR_FUNCTION_FAILED;

		return CKR_OK;
	}
	else
		return CKR_OPERATION_NOT_INITIALIZED;
}

/* C_DecryptUpdate continues a multiple-part decryption
 * operation. */
CK_RV C_DecryptUpdate
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	logFunc(__func__);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptFinal finishes a multiple-part decryption
 * operation. */
CK_RV C_DecryptFinal
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	logFunc(__func__);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

