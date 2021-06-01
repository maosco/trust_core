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
#include "common_defs.h"
#include "tc_api.h"
#include <string.h>
#include <multosio.h>
#include <stdio.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <pthread.h>		// For Mutex
#endif
#include <sys/types.h>

// Global variables
CK_BBOOL g_bInitialised = 0;
CK_BBOOL g_bDeviceOK = 0;
multosChipData_t g_deviceInfo;
CK_ULONG g_ulSessionCount = 0;
CK_FLAGS g_SessionFlags[MAX_SESSIONS+1];
CK_BYTE g_SessionIsOpen[MAX_SESSIONS+1];
CK_USER_TYPE g_loggedInUser = NO_LOGGED_IN_USER;
CK_FUNCTION_LIST g_funclist;

// Mutex variables
#ifdef _WIN32
HANDLE processLock;
#else
pthread_mutex_t processLock;
#endif

/* C_Initialize initializes the Cryptoki library. */
CK_RV C_Initialize(
  CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
)
{
	CK_C_INITIALIZE_ARGS_PTR pArgs;
	CK_C_INITIALIZE_ARGS args;
	char msg[64];
	int i;
	int appIsAlreadySelected = 0;

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(pInitArgs)
	{
		pArgs = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
		args = *pArgs;

		// This library doesn't support threads, so CKF_LIBRARY_CANT_CREATE_OS_THREADS is irrelevant
		if(args.flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
			logFunc("...CKF_LIBRARY_CANT_CREATE_OS_THREADS set");

		// Can't support external mutex functions at the moment
#ifdef _WIN32
		if((args.flags & CKF_OS_LOCKING_OK) && args.LockMutex != NULL_PTR)
#else
		if((args.flags & CKF_OS_LOCKING_OK) && args.CreateMutex != NULL_PTR)
#endif
		{
			logFunc("...can't lock");
			return CKR_CANT_LOCK;
		}

		if(args.pReserved != NULL)
		{
			logFunc("...args bad");
			return CKR_ARGUMENTS_BAD;
		}
	}

	// Don't allow multiple initialisations within a single process
	if(g_bInitialised)
	{
		logFunc("...already initialised");
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	// Check to see if the app has been selected in another process already by calling an app function that has no impact
	appIsAlreadySelected = tcAskRandom(8,(BYTE*)msg);
	sprintf(msg,"...already selected=%d",appIsAlreadySelected);
	logFunc(msg);

	if(!appIsAlreadySelected)
	{
		g_bDeviceOK = 0;
		g_ulSessionCount = 0;

		// Reset the chip. Selects the OS
		if(!multosReset())
		{
			logFunc("...reset failed");
			return CKR_FUNCTION_FAILED;
		}

		// Get the hardware / OS information
		logFunc("......getting chip info...");
		multosGetChipInfo(MCDNO_VALID | APPDATA_VALID | BUILDNO_VALID, &g_deviceInfo);

		logFunc("......selecting app");
		if(!tcSelectApp())
		{
			logFunc("...app selection failed");
			return CKR_FUNCTION_FAILED;
		}
	}
	else
	{
		// We can't deselect the app in order to get the chip info because it could mess up other processes. So for this process, we can't say
		// what the device related info is
		g_deviceInfo.validFields = 0;
	}

	// Chip OK if get to here
	g_bDeviceOK = 1;
	g_bInitialised = 1;

	// Initialise session info (valid session IDs are 1..MAX_SESSIONS)
	for(i=0;i<=MAX_SESSIONS;i++)
	{
		g_SessionFlags[i] = 0;
		g_SessionIsOpen[i] = 0;
	}

	// Create mutex needed for safe multi-thread access
#ifdef _WIN32
	processLock = CreateMutex(NULL,FALSE,L"ProcessLock");
#else
	pthread_mutex_init(&processLock,NULL);
#endif
	logFunc("...ok");

	return CKR_OK;
}


/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_RV C_Finalize(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(pReserved)
		return CKR_ARGUMENTS_BAD;

	if(g_bInitialised)
	{
		g_bInitialised = 0;
		g_bDeviceOK = 0;
		g_ulSessionCount = 0;
		//multosDeselectCurrApplication();

		// Dispose of mutex
#ifdef _WIN32
		CloseHandle(processLock);
#else
		pthread_mutex_destroy(&processLock);
#endif
		return CKR_OK;
	}
	else
		return CKR_CRYPTOKI_NOT_INITIALIZED;
}


/* C_GetInfo returns general information about Cryptoki. */
CK_RV C_GetInfo(
  CK_INFO_PTR   pInfo  /* location that receives information */
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(pInfo)
	{
		pInfo->cryptokiVersion.major = 2;
		pInfo->cryptokiVersion.minor = CRYPTOKI_MINOR_VERSION;
		pInfo->libraryVersion.major = LIBRARY_MAJOR_VERSION;
		pInfo->libraryVersion.minor = LIBRARY_MINOR_VERSION;
		strcpy((char*)pInfo->manufacturerID,LIB_MANUFACTURER_ID);
		padWithSpaces((char*)pInfo->manufacturerID,32);
		strcpy((char*)pInfo->libraryDescription,LIB_DESC);
		padWithSpaces((char*)pInfo->libraryDescription,32);
		pInfo->flags = 0;
	}
	else
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


/* C_GetFunctionList returns the function list. */
CK_RV C_GetFunctionList(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList   /*receives pointer to
                                            * function list*/
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if (ppFunctionList == NULL)
		return CKR_ARGUMENTS_BAD;

	// Erase the func list so anything not explicitly set is zeroed
	memset(&g_funclist,0,sizeof(g_funclist));

	g_funclist.version.major = 2;
	g_funclist.version.minor = CRYPTOKI_MINOR_VERSION;
	g_funclist.C_CancelFunction = C_CancelFunction;
	g_funclist.C_CloseAllSessions = C_CloseAllSessions;
	g_funclist.C_CloseSession = C_CloseSession;
	g_funclist.C_CopyObject = C_CopyObject;
	g_funclist.C_CreateObject = C_CreateObject;
	g_funclist.C_Decrypt = C_Decrypt;
	g_funclist.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
	g_funclist.C_DecryptFinal = C_DecryptFinal;
	g_funclist.C_DecryptInit = C_DecryptInit;
	g_funclist.C_DecryptUpdate = C_DecryptUpdate;
	g_funclist.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
	g_funclist.C_DeriveKey = C_DeriveKey;
	g_funclist.C_DestroyObject = C_DestroyObject;
	g_funclist.C_Digest = C_Digest;
	g_funclist.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
	g_funclist.C_DigestFinal = C_DigestFinal;
	g_funclist.C_DigestInit = C_DigestInit;
	g_funclist.C_DigestKey = C_DigestKey;
	g_funclist.C_DigestUpdate = C_DigestUpdate;
	g_funclist.C_Encrypt = C_Encrypt;
	g_funclist.C_EncryptFinal = C_EncryptFinal;
	g_funclist.C_EncryptInit = C_EncryptInit;
	g_funclist.C_EncryptUpdate = C_EncryptUpdate;
	g_funclist.C_Finalize = C_Finalize;
	g_funclist.C_FindObjects = C_FindObjects;
	g_funclist.C_FindObjectsFinal = C_FindObjectsFinal;
	g_funclist.C_FindObjectsInit = C_FindObjectsInit;
	g_funclist.C_GenerateKey = C_GenerateKey;
	g_funclist.C_GenerateKeyPair = C_GenerateKeyPair;
	g_funclist.C_GenerateRandom = C_GenerateRandom;
	g_funclist.C_GetAttributeValue = C_GetAttributeValue;
	g_funclist.C_GetFunctionList = C_GetFunctionList;
	g_funclist.C_GetFunctionStatus = C_GetFunctionStatus;
	g_funclist.C_GetInfo = C_GetInfo;
	g_funclist.C_GetMechanismInfo = C_GetMechanismInfo;
	g_funclist.C_GetMechanismList = C_GetMechanismList;
	g_funclist.C_GetObjectSize = C_GetObjectSize;
	g_funclist.C_GetOperationState = C_GetOperationState;
	g_funclist.C_GetSessionInfo = C_GetSessionInfo;
	g_funclist.C_GetSlotInfo = C_GetSlotInfo;
	g_funclist.C_GetSlotList = C_GetSlotList;
	g_funclist.C_GetTokenInfo = C_GetTokenInfo;
	g_funclist.C_InitPIN = C_InitPIN;
	g_funclist.C_InitToken = C_InitToken;
	g_funclist.C_Initialize = C_Initialize;
	g_funclist.C_Login = C_Login;
	g_funclist.C_Logout = C_Logout;
	g_funclist.C_OpenSession = C_OpenSession;
	g_funclist.C_SeedRandom = C_SeedRandom;
	g_funclist.C_SetAttributeValue = C_SetAttributeValue;
	g_funclist.C_SetOperationState = C_SetOperationState;
	g_funclist.C_SetPIN = C_SetPIN;
	g_funclist.C_Sign = C_Sign;
	g_funclist.C_SignEncryptUpdate = C_SignEncryptUpdate;
	g_funclist.C_SignFinal = C_SignFinal;
	g_funclist.C_SignInit = C_SignInit;
	g_funclist.C_SignRecover = C_SignRecover;
	g_funclist.C_SignRecoverInit = C_SignRecoverInit;
	g_funclist.C_SignUpdate = C_SignUpdate;
	g_funclist.C_UnwrapKey = C_UnwrapKey;
	g_funclist.C_Verify = C_Verify;
	g_funclist.C_VerifyFinal = C_VerifyFinal;
	g_funclist.C_VerifyInit = C_VerifyInit;
	g_funclist.C_VerifyRecover = C_VerifyRecover;
	g_funclist.C_VerifyRecoverInit = C_VerifyRecoverInit;
	g_funclist.C_VerifyUpdate = C_VerifyUpdate;
	g_funclist.C_WaitForSlotEvent = C_WaitForSlotEvent;
	g_funclist.C_WrapKey = C_WrapKey;


	*ppFunctionList = &g_funclist;

	return CKR_OK;
}
