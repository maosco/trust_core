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

#include <stdio.h>
#include <string.h>
#include "pkcs11.h"
#include "tc_api.h"
#include "common_defs.h"
#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>		// For Mutex
#else
#include <Windows.h>
#endif

// Local variables
static BYTE bSigAlgo = 0;

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_USER_TYPE g_loggedInUser;
extern CK_BYTE g_SessionIsOpen[];

// Lock for critical sections
#ifdef _WIN32
extern HANDLE processLock;
#else
extern pthread_mutex_t processLock;
#endif
#ifdef _WIN32
#define COMMON_CHECKS() \
	if(!g_bInitialised) \
	{\
		ReleaseMutex(processLock);\
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	}\
	if(!g_bDeviceOK) \
	{\
		ReleaseMutex(processLock);\
		return CKR_DEVICE_REMOVED; \
	}\
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
	{\
		ReleaseMutex(processLock);\
		return CKR_SESSION_HANDLE_INVALID; \
	}\
	if(!g_SessionIsOpen[hSession]) \
	{\
		ReleaseMutex(processLock);\
		return CKR_SESSION_HANDLE_INVALID; \
	}\
	if(g_loggedInUser == NO_LOGGED_IN_USER) \
	{\
		ReleaseMutex(processLock);\
		return CKR_USER_NOT_LOGGED_IN; \
	}
#else
#define COMMON_CHECKS() \
	if(!g_bInitialised) \
	{\
		pthread_mutex_unlock(&processLock);\
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	}\
	if(!g_bDeviceOK) \
	{\
		pthread_mutex_unlock(&processLock);\
		return CKR_DEVICE_REMOVED; \
	}\
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
	{\
		pthread_mutex_unlock(&processLock);\
		return CKR_SESSION_HANDLE_INVALID; \
	}\
	if(!g_SessionIsOpen[hSession]) \
	{\
		pthread_mutex_unlock(&processLock);\
		return CKR_SESSION_HANDLE_INVALID; \
	}\
	if(g_loggedInUser == NO_LOGGED_IN_USER) \
	{\
		pthread_mutex_unlock(&processLock);\
		return CKR_USER_NOT_LOGGED_IN; \
	}
#endif

// Local flags
static CK_BBOOL bInitialised = FALSE;

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 *  cannot be recovered from the signature (e.g. DSA). */
CK_RV C_VerifyInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	WORD wFileSize;
	CK_RV status = CKR_OK;

#ifdef _WIN32
	WaitForSingleObject(processLock,INFINITE);
#else
	pthread_mutex_lock(&processLock);
#endif

	logFunc(__func__);

	COMMON_CHECKS();

	switch(pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:
			bSigAlgo = TC_ALGO_RSA;

			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				status = CKR_MECHANISM_PARAM_INVALID;

			// Set the algo in the template
			else if(!tcMseSetAlgo(bSigAlgo,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;

			// Select and preload the key to use if not already present
			else if(hKey != RSA_PUBLIC_KEY_SESSION_OBJECT)
			{
				if(!tcSelectEF(hKey,&wFileSize))
					status =  CKR_KEY_HANDLE_INVALID;

				else if(!tcPreloadPublicKey(wFileSize))
					status = CKR_FUNCTION_FAILED;
			}
			break;

		case CKM_ECDSA:
			bSigAlgo = TC_ALGO_ECDSA;

			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				status = CKR_MECHANISM_PARAM_INVALID;

			// Set the algo in the template
			else if(!tcMseSetAlgo(bSigAlgo,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;

			// Select and preload the key to use (if not already a session object loaded)
			else if(hKey != EC_PUBLIC_KEY_SESSION_OBJECT)
			{
				if(!tcSelectEF(hKey,&wFileSize))
					status =  CKR_KEY_HANDLE_INVALID;


				else if(!tcPreloadPublicKey(wFileSize))
					status = CKR_FUNCTION_FAILED;
			}
			break;

		default:
			bSigAlgo = 0;
			status = CKR_MECHANISM_INVALID;
			break;
	}
	if (status != CKR_OK)
#ifdef _WIN32
		ReleaseMutex(processLock);
#else
		pthread_mutex_unlock(&processLock);
#endif
	else
		bInitialised = TRUE;
	return status;
}



/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
CK_RV C_Verify
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	int status = 0;
	BYTE abBuffer[TC_DECRYPT_BUFF_SIZE];
	WORD wRecoveredLen = 0;
	BYTE *pRecovered;
	WORD wLenToCopy = 0;

	logFunc(__func__);

	COMMON_CHECKS();

	if(!bInitialised)
	{
#ifdef _WIN32
		ReleaseMutex(processLock);
#else
		pthread_mutex_unlock(&processLock);
#endif
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	switch(bSigAlgo)
	{
		case TC_ALGO_RSA:
			// Decrypt the signature into a working buffer
			wLenToCopy = ulSignatureLen < sizeof(abBuffer) ? ulSignatureLen : sizeof(abBuffer);
			memcpy(abBuffer,pSignature,wLenToCopy);
			status = tcVerify(abBuffer,wLenToCopy);

			// Check and Remove padding from decrypted signature (PKCS v1,5 type 1)
			if(abBuffer[0] == 0 && abBuffer[1] == 1)
			{
				pRecovered = abBuffer + 2;
				wRecoveredLen = wLenToCopy - 2;
				while(*pRecovered != 0 && wRecoveredLen > 0)
				{
					pRecovered++;
					wRecoveredLen--;
				}
				if(wRecoveredLen > 0)
				{
					pRecovered++;
					wRecoveredLen--;
				}

				// Compare the computed hash against the recovered hash
				if(wRecoveredLen != ulDataLen || memcmp(pRecovered,pData,wRecoveredLen) != 0)
					status = 2;
			}
			else
			{
				status = 2;
			}
			break;

		case TC_ALGO_ECDSA:
			// Arrange the input as needed
			// Signature to be verified (pSignature) | Hash (pData)
			memcpy(abBuffer,pSignature,ulSignatureLen);
			memcpy(abBuffer+ulSignatureLen,pData,ulDataLen);
			wLenToCopy = ulSignatureLen + ulDataLen;

			// Call the verify function.
			status = tcVerify(abBuffer,wLenToCopy);
		break;

		default:
			status = 3;
			break;
	}

	// Init is required again
	bInitialised = FALSE;
#ifdef _WIN32
	ReleaseMutex(processLock);
#else
	pthread_mutex_unlock(&processLock);
#endif

	if(status == 1)
		return CKR_SIGNATURE_LEN_RANGE;

	if(status == 2)
		return CKR_SIGNATURE_INVALID;

	if(status == 3)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}


/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
CK_RV C_VerifyUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* signed data */
  CK_ULONG          ulPartLen  /* length of signed data */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
CK_RV C_VerifyFinal
(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pSignature,     /* signature to verify */
  CK_ULONG          ulSignatureLen  /* signature length */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecoverInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecover
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}
