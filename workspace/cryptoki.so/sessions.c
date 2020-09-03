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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>		// For Mutex
#include <sys/types.h>

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_ULONG g_ulSessionCount;
extern CK_FLAGS g_SessionFlags[];
extern CK_BYTE g_SessionIsOpen[];
extern CK_USER_TYPE g_loggedInUser;

#define COMMON_CHECKS() \
	if(!g_bInitialised) \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	if(!g_bDeviceOK) \
		return CKR_DEVICE_REMOVED; \
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(!g_SessionIsOpen[hSession]) \
		return CKR_SESSION_HANDLE_INVALID;	// Was CKR_SESSION_CLOSED

// Lock for critical sections
extern pthread_mutex_t processLock;

CK_RV C_OpenSession
(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	char msg[64];
	CK_RV status = CKR_OK;
	int i;

	pthread_mutex_lock(&processLock);

	sprintf(msg,"%s tid=%d parent=%d",__func__, (int)gettid(),getppid());
	logFunc(msg);

	if(!g_bInitialised)
		status = CKR_CRYPTOKI_NOT_INITIALIZED;

	else if(slotID != 1)
		status = CKR_SLOT_ID_INVALID;

	else if(!g_bDeviceOK)
		status = CKR_TOKEN_NOT_PRESENT;

	else if(!(flags & CKF_SERIAL_SESSION))
		status = CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	// Don't support callbacks
	else if( Notify != NULL_PTR )
		status = CKR_DEVICE_ERROR;

	else if(phSession == NULL)
		status = CKR_ARGUMENTS_BAD;
/*
	else if(g_ulSessionCount == 0)
	{
		if(!tcSelectApp())
			status = CKR_FUNCTION_FAILED;
	}
*/
	else if (g_ulSessionCount+1 >= MAX_SESSIONS)
		status = CKR_SESSION_COUNT;

	if(status == CKR_OK)
	{
		g_ulSessionCount++;

		// Find free session slot - there will be one because of previous guards
		for(i=1;i<=MAX_SESSIONS && g_SessionIsOpen[i];i++);

		// Store session info
		g_SessionFlags[i] = flags;
		g_SessionIsOpen[i] = 1;

		// Return session ID
		*phSession = i;

		sprintf(msg,"==> %d",i);
		logFunc(msg);
	}
	pthread_mutex_unlock(&processLock);
	return status;
}

/* C_CloseSession closes a session between an application and a
 * token. */
CK_RV C_CloseSession
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);

	COMMON_CHECKS();

	// Update session related globals
	g_ulSessionCount--;
	g_SessionFlags[hSession] = 0;
	g_SessionIsOpen[hSession] = 0;

	/* Not sure about this...
	// If all sessions closed
	if(g_ulSessionCount == 0)
		// Flag that no users are logged in
		g_loggedInUser = NO_LOGGED_IN_USER;
	*/

	return CKR_OK;
}


/* C_CloseAllSessions closes all sessions with a token.
 */
CK_RV C_CloseAllSessions
(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
	int s;
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	for(s=1;s<=MAX_SESSIONS;s++)
		if(g_SessionIsOpen[s])
			C_CloseSession(s);

	return CKR_OK;
}


/* C_GetSessionInfo obtains information about the session. */
CK_RV C_GetSessionInfo
(
  CK_SESSION_HANDLE   hSession,  /* the session's handle */
  CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);


	COMMON_CHECKS();

	if(pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = 1;
	pInfo->flags = g_SessionFlags[hSession];
	pInfo->ulDeviceError = 0; // Unused

	// If read/write session
	if(g_SessionFlags[hSession] & CKF_RW_SESSION)
	{
		switch(g_loggedInUser)
		{
			case CKU_SO:
				pInfo->state = CKS_RW_SO_FUNCTIONS;
				break;
			case CKU_USER:
				pInfo->state = CKS_RW_USER_FUNCTIONS;
				break;
			case CKU_CONTEXT_SPECIFIC:
				pInfo->state = SESSION_STATE_KEYMAN;
				break;
			default:
				pInfo->state = CKS_RW_PUBLIC_SESSION;
				break;
		}
	}
	else
	{
		// RO session
		switch(g_loggedInUser)
		{
			case CKU_SO:
				pInfo->state = 99; // Invalid state
				break;
			case CKU_USER:
				pInfo->state = CKS_RO_USER_FUNCTIONS;
				break;
			default:
				pInfo->state = CKS_RO_PUBLIC_SESSION;
				break;
		}
	}
	return CKR_OK;
}


/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_RV C_GetOperationState
(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_RV C_SetOperationState
(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);

	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Login logs a user into a token. */
CK_RV C_Login
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	BYTE pinData[12];
	int pinVerificationStatus;
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);


	COMMON_CHECKS();

	// CKU_CONTEXT_SPECIFIC is used for key management
	if(userType != CKU_SO && userType != CKU_USER && userType != CKU_CONTEXT_SPECIFIC)
		return CKR_USER_TYPE_INVALID;

	// SO can't log into a read-only session
	if(!(g_SessionFlags[hSession] & CKF_RW_SESSION) && userType == CKU_SO)
		return CKR_SESSION_READ_ONLY_EXISTS;

	// Now check to see if anyone is already logged in
	if(g_loggedInUser != NO_LOGGED_IN_USER)
	{
		if(g_loggedInUser == userType)
			return CKR_USER_ALREADY_LOGGED_IN;
		else
			return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
	}

	// Set up given PIN in the format required.
	memset(pinData,0xFF,12);
	memcpy(pinData,pPin,ulPinLen);

	// Try to log in
	pinVerificationStatus = tcVerifyPIN(userType,pinData);
	memset(pinData,0x00,12);
	if(pinVerificationStatus)
	{
		g_loggedInUser = userType;
		return CKR_OK;
	}
	else
	{
		// See if PIN is blocked
		pinVerificationStatus = tcVerifyPIN(userType,NULL);
		if(pinVerificationStatus <= 0)
			return CKR_PIN_LOCKED;
		else
			return CKR_PIN_INCORRECT;
	}
}


/* C_Logout logs a user out from a token. */
CK_RV C_Logout
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);

	COMMON_CHECKS();

	if(g_loggedInUser == NO_LOGGED_IN_USER)
		return CKR_USER_NOT_LOGGED_IN;

	g_loggedInUser = NO_LOGGED_IN_USER;
	return CKR_OK;
}
