/*
 * Copyright (c) 2020, MAOSCO Ltd
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
#include <unistd.h>
#include <pthread.h>		// For Mutex
#include <sys/types.h>

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_BYTE g_SessionIsOpen[];
extern CK_USER_TYPE g_loggedInUser;

// Local flags
static CK_BBOOL bInitialised = FALSE;

// Lock for critical sections
extern pthread_mutex_t processLock;


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

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
CK_RV C_SignInit
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	char msg[64];
	CK_RV status;
	CK_TLS_MAC_PARAMS_PTR pMacParams;
	BYTE bAlgo;

	pthread_mutex_lock(&processLock);

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	COMMON_CHECKS();
	status = CKR_OK;

	switch(pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:
			// The key must be one of the two supported
			if(hKey != 0x6100 && hKey != 0x6101)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_RSA,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_SHA1_RSA_PKCS_PSS:
			// The key must be one of the two supported
			if(hKey != 0x6100 && hKey != 0x6101)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_PSS_SHA1,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_SHA256_RSA_PKCS_PSS:
			// The key must be one of the two supported
			if(hKey != 0x6100 && hKey != 0x6101)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_PSS_SHA256,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_ECDSA:
			// Must be a EC key
			if((hKey & TC_EFTYPE_EC_PRIVKEY) != TC_EFTYPE_EC_PRIVKEY)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_ECDSA,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_SHA_1_HMAC:
			// Must be a secret key
			if((hKey & TC_EFTYPE_SECRET) != TC_EFTYPE_SECRET)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_SHA1_HMAC,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_SHA256_HMAC:
			// Must be a secret key
			if((hKey & TC_EFTYPE_SECRET) != TC_EFTYPE_SECRET)
				status = CKR_KEY_HANDLE_INVALID;

			// Set the algo in the template
			if(status == CKR_OK && !tcMseSetAlgo(TC_ALGO_SHA256_HMAC,TC_TEMPLATE_DIGITAL_SIG))
				status = CKR_FUNCTION_FAILED;
			break;

		case CKM_TLS12_MAC:
			// Must be a secret key
			if((hKey & TC_EFTYPE_SECRET) != TC_EFTYPE_SECRET)
				status = CKR_KEY_HANDLE_INVALID;

			// Check parameters
			status = CKR_MECHANISM_PARAM_INVALID;
			if(pMechanism->pParameter != NULL_PTR && pMechanism->ulParameterLen == sizeof(CK_TLS_MAC_PARAMS))
			{
				pMacParams = (CK_TLS_MAC_PARAMS_PTR)pMechanism->pParameter;
				if(pMacParams->ulMacLength == 12 && pMacParams->prfHashMechanism == CKM_SHA256 && (pMacParams->ulServerOrClient == 1 || pMacParams->ulServerOrClient == 2))
				{
					// Set the algo in the template
					if(pMacParams->ulServerOrClient == 1)
						bAlgo = TC_ALGO_TLS12_MAC_SERVER;
					else
						bAlgo = TC_ALGO_TLS12_MAC_CLIENT;

					if(tcMseSetAlgo(bAlgo,TC_TEMPLATE_DIGITAL_SIG))
						status = CKR_OK;
					else
						status = CKR_FUNCTION_FAILED;
				}
			}
			break;

		default:
			status = CKR_MECHANISM_INVALID;
			break;
	}

	// Set the key to use
	if(status == CKR_OK && !tcMseSetKeyFile(hKey,TC_TEMPLATE_DIGITAL_SIG))
		status = CKR_KEY_HANDLE_INVALID;

	if (status != CKR_OK)
		pthread_mutex_unlock(&processLock);
	else
		bInitialised = TRUE;
	return status;
}


/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
CK_RV C_Sign
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	int status;
	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	COMMON_CHECKS();

	if(!bInitialised)
	{
		pthread_mutex_unlock(&processLock);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	sprintf(msg,"pSig=0x%x, sigLen=%d",(unsigned)pSignature,(unsigned)*pulSignatureLen);
	logFunc(msg);

	status = tcSign(pData, (WORD) ulDataLen, pSignature, (WORD*) pulSignatureLen);
	if(status == 0)
		logFunc("...OK");

	//pthread_mutex_unlock(&processLock);

	if(status == 2)
	{
		pthread_mutex_unlock(&processLock);
		return CKR_BUFFER_TOO_SMALL;
	}

	// This makes the BIG assumption that C_SIGN will be called again with pSignature set to a value
	if(status == 0 && pSignature == 0)
		return CKR_OK;

	// Anything else and init is required again
	bInitialised = FALSE;
	pthread_mutex_unlock(&processLock);

	if(status == 1)
		return CKR_DATA_LEN_RANGE;

	if(status == 3)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}


/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature. */
CK_RV C_SignUpdate
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* the data to sign */
  CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature. */
CK_RV C_SignFinal
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_RV C_SignRecoverInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_RV C_SignRecover
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	logFunc(__func__);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

