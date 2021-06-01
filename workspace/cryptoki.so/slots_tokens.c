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

/*
 *  NOTE: The current driver architecture assumes that there will only ever be one
 *  attached MULTOS device (token) and that it may be connected or disconnected from its interface (slot).
 *  The physical connection layer is decoupled by multosio.so and at the moment has no way of getting any info on
 *  the physical connection from the underlying driver.
 */

#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif
#include <stdio.h>
#include "pkcs11.h"
#include "tc_api.h"
#include "common_defs.h"
#include <sys/types.h>

// Local constants
static CK_MECHANISM_TYPE supportedMechanisms[] = {CKM_RSA_PKCS_KEY_PAIR_GEN , CKM_RSA_PKCS, CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512,
		CKM_TLS12_KEY_AND_MAC_DERIVE, CKM_TLS12_MASTER_KEY_DERIVE, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_AES_CBC, CKM_AES_GCM,
		CKM_SHA_1_HMAC, CKM_SHA256_HMAC, CKM_TLS12_MAC, CKM_AES_KEY_GEN, CKM_SSL3_PRE_MASTER_KEY_GEN, CKM_ECDSA, CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE};

static int numMechanisms = sizeof(supportedMechanisms);

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern multosChipData_t g_deviceInfo;
extern CK_ULONG g_ulSessionCount;
extern CK_FLAGS g_SessionFlags[];
extern CK_BYTE g_SessionIsOpen[];
extern CK_USER_TYPE g_loggedInUser;

/* C_GetSlotList obtains a list of slots in the system. */

CK_RV C_GetSlotList(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
	char msg[64];
	CK_ULONG slotCount = 1;

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	// If we need to check if a token is currently connected
	if(tokenPresent && !g_bDeviceOK)
		slotCount = 0;

	// If a list of slots is needed
	if(pSlotList && slotCount > 0)
	{
		// Error if pSlotList isn't big enough to hold all the slot numbers
		if(*pulCount < slotCount)
			return CKR_BUFFER_TOO_SMALL;

		// There is only one slot and it will be numbered 1
		*pSlotList = 1;
	}

	// Return the slot count
	*pulCount = slotCount;

	return CKR_OK;
}

/* C_GetSlotInfo obtains information about a particular slot in the system.
 * However, the physical connection layer is decoupled by multosio.so and at the moment has no way of getting any info on
 * the physical connection from the underlying driver. So we have to hardcode some info here.
 */
CK_RV C_GetSlotInfo(
  CK_SLOT_ID       slotID,  /* the ID of the slot */
  CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	if(pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo,0,sizeof(CK_SLOT_INFO));

	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	if(g_bDeviceOK)
		pInfo->flags |= CKF_TOKEN_PRESENT;

	strcpy((char*)pInfo->manufacturerID,SLOT_MANUFACTURER_ID);
	padWithSpaces((char *)pInfo->manufacturerID,32);

	multosHALInfo((char *)pInfo->slotDescription,&(pInfo->firmwareVersion.major),&(pInfo->firmwareVersion.minor));
	padWithSpaces((char *)pInfo->slotDescription,64);

	return CKR_OK;
}

/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_RV C_GetTokenInfo(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
	char msg[64];
	int triesLeft;

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	if(!g_bDeviceOK)
		return CKR_TOKEN_NOT_PRESENT;

	if(pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	// Wipe the structure before starting, so unset values are zero / NULL
	memset(pInfo,0,sizeof(CK_TOKEN_INFO));

	// Fill in the bits of the info structure that we can
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;
	tcGetVersion(&(pInfo->firmwareVersion.major),&(pInfo->firmwareVersion.minor));

	pInfo->flags = CKF_LOGIN_REQUIRED | CKF_RNG | CKF_TOKEN_INITIALIZED;

	// PIN related flags
	triesLeft = tcVerifyPIN(CKU_USER,NULL);
	if(triesLeft == 1)
		pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
	else if (triesLeft == 2)
		pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
	else if (triesLeft == 0)
		pInfo->flags |= CKF_USER_PIN_LOCKED;
	else
		pInfo->flags |= CKF_USER_PIN_INITIALIZED;

	triesLeft = tcVerifyPIN(CKU_SO,NULL);
	if(triesLeft == 1)
		pInfo->flags |= CKF_SO_PIN_FINAL_TRY;
	else if (triesLeft == 2)
		pInfo->flags |= CKF_SO_PIN_COUNT_LOW;
	else if (triesLeft == 0)
			pInfo->flags |= CKF_SO_PIN_LOCKED;

	strcpy((char*)pInfo->manufacturerID,TOKEN_MANUFACTURER_ID);
	padWithSpaces((char*)(pInfo->manufacturerID),32);
	pInfo->ulMaxSessionCount = MAX_SESSIONS;
	pInfo->ulSessionCount = g_ulSessionCount;
	pInfo->ulMaxPinLen = TC_PIN_SIZE;
	pInfo->ulMinPinLen = 4;
	if(g_deviceInfo.validFields & MCDNO_VALID)
		strncpy((char*)pInfo->serialNumber,(char*)g_deviceInfo.mcdNumber,8);
	else
		pInfo->serialNumber[0] = 0;
	padWithSpaces((char*)(pInfo->serialNumber),16);

	// Slot label
	pInfo->label[0] = 'C';
	pInfo->label[1] = 'H';
	pInfo->label[2] = 'I';
	pInfo->label[3] = 'P';
	pInfo->label[4] = '1';
	pInfo->label[5] = 0;
	padWithSpaces((char*)pInfo->label,32);

	strcpy((char*)pInfo->model,TOKEN_MODEL_ID);
	padWithSpaces((char*)pInfo->model,16);
	return CKR_OK;

}

/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_RV C_GetMechanismList
(
  CK_SLOT_ID            slotID,          /* ID of token's slot */
  CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
  CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	int i;
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	if(!g_bDeviceOK)
		return CKR_TOKEN_NOT_PRESENT;

	if(pulCount == NULL)
		return CKR_ARGUMENTS_BAD;

	if(pMechanismList)
	{
		if(*pulCount < (unsigned)numMechanisms)
		{
			*pulCount = numMechanisms;
			return CKR_BUFFER_TOO_SMALL;
		}

		for(i = 0; i < numMechanisms; i++)
			pMechanismList[i] = supportedMechanisms[i];
	}
	*pulCount = numMechanisms;
	return CKR_OK;
}

/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_RV C_GetMechanismInfo
(
  CK_SLOT_ID            slotID,  /* ID of the token's slot */
  CK_MECHANISM_TYPE     type,    /* type of mechanism */
  CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	if(!g_bDeviceOK)
		return CKR_TOKEN_NOT_PRESENT;

	if(pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	pInfo->flags = 0;
	pInfo->ulMinKeySize = 0;
	pInfo->ulMaxKeySize = 0;

	switch(type) {
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 2048;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;
		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 2048;
			pInfo->flags = CKF_WRAP + CKF_VERIFY + CKF_DECRYPT + CKF_ENCRYPT + CKF_SIGN;
			break;
		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_UNWRAP + CKF_WRAP + CKF_DECRYPT + CKF_ENCRYPT;
			break;
		case CKM_AES_GCM:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_DECRYPT + CKF_ENCRYPT;
			break;
		case CKM_AES_KEY_GEN:
			pInfo->ulMinKeySize = 16;
			pInfo->ulMaxKeySize = 32;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_SSL3_PRE_MASTER_KEY_GEN:
			pInfo->ulMinKeySize = 48;
			pInfo->ulMaxKeySize = 48;
			pInfo->flags = CKF_GENERATE;
			break;
		case CKM_SHA_1:
		case CKM_SHA256:
		case CKM_SHA384:
		case CKM_SHA512:
			pInfo->flags = CKF_DIGEST;
			break;
		case CKM_TLS12_KEY_AND_MAC_DERIVE:
			pInfo->flags = CKF_DERIVE;
			break;
		case CKM_TLS12_MASTER_KEY_DERIVE:
			pInfo->flags = CKF_DERIVE;
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 2048;
			pInfo->flags = CKF_SIGN;
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			pInfo->ulMinKeySize = 512;
			pInfo->ulMaxKeySize = 2048;
			pInfo->flags = CKF_SIGN;
			break;
		case CKM_SHA_1_HMAC:
			pInfo->flags = CKF_SIGN;
			break;
		case CKM_SHA256_HMAC:
			pInfo->flags = CKF_SIGN;
			break;
		case CKM_TLS12_MAC:
			pInfo->flags = CKF_SIGN;
			break;
		case CKM_ECDSA:
			pInfo->flags = CKF_EC_F_P + CKF_EC_NAMEDCURVE + CKF_EC_UNCOMPRESS + CKF_SIGN;
			pInfo->ulMinKeySize = 256;
			pInfo->ulMaxKeySize = 521;
			break;
		case CKM_EC_KEY_PAIR_GEN:
			pInfo->flags = CKF_EC_F_P + CKF_EC_NAMEDCURVE + CKF_EC_UNCOMPRESS + CKF_GENERATE_KEY_PAIR;
			pInfo->ulMinKeySize = 256;
			pInfo->ulMaxKeySize = 521;
			break;
		case CKM_ECDH1_DERIVE:
			pInfo->flags = CKF_EC_F_P + CKF_EC_NAMEDCURVE + CKF_EC_UNCOMPRESS + CKF_DERIVE;
			pInfo->ulMinKeySize = 256;
			pInfo->ulMaxKeySize = 521;
			break;
		default:
			return CKR_MECHANISM_INVALID;
			break;
	}
	return CKR_OK;
}

// MULTOS App is temporarily selected.
// TODO: This could be implemented as a single internal function in the Trust Core app.
CK_RV C_InitToken
(
  CK_SLOT_ID      slotID,    /* ID of the token's slot */
  CK_CHAR_PTR     pPin,      /* the SO's initial PIN */
  CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
  CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	BYTE pinData[TC_PIN_SIZE];
	BYTE defaultPIN[] = { 0x31, 0x32, 0x33, 0x34, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	BYTE tempPIN[] = { 0x39, 0x39, 0x39, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	char msg[64];
	CK_RV status = CKR_OK;

	int i;

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(slotID != 1)
		return CKR_SLOT_ID_INVALID;

	if(!g_bDeviceOK)
		return CKR_TOKEN_NOT_PRESENT;

	if(g_ulSessionCount > 0)
		return CKR_SESSION_EXISTS;

	if(ulPinLen > TC_PIN_SIZE)
		return CKR_PIN_LEN_RANGE;

	if( !tcSelectApp() )
		return CKR_TOKEN_NOT_PRESENT;

	// Having just selected the application, no PIN should be current.
	g_loggedInUser = NO_LOGGED_IN_USER;

	// Set up given PIN in the format required.
	memset(pinData,0xFF,TC_PIN_SIZE);
	memcpy(pinData,pPin,ulPinLen);

	// Attempt authentication with default 1234 pin
	if( tcVerifyPIN(CKU_SO, defaultPIN))
	{
		// Set SO-PIN to that provided in the function call
		if (!tcSetPIN(CKU_SO, defaultPIN, pinData))
		{
			memset(pinData,0,TC_PIN_SIZE);
			multosDeselectCurrApplication();
			return CKR_FUNCTION_FAILED;
		}

		// Verify with new PIN
		if ( !tcVerifyPIN(CKU_SO, pinData) )
		{
			memset(pinData,0,TC_PIN_SIZE);
			multosDeselectCurrApplication();
			return CKR_PIN_INCORRECT;
		}
	}
	// else attempt authenticate with the SO-PIN provided in the function call
	else
	{
		if ( !tcVerifyPIN(CKU_SO, pinData) )
		{
			memset(pinData,0,TC_PIN_SIZE);
			multosDeselectCurrApplication();
			return CKR_PIN_INCORRECT;
		}
	}

	// Set the USER PIN to a known value...
	if(!tcSetPINSOLoggedIn(CKU_USER,tempPIN))
	{
		memset(pinData,0,TC_PIN_SIZE);
		multosDeselectCurrApplication();
		return CKR_FUNCTION_FAILED;
	}
	//... and run down it's retry counter to lock it
	tcVerifyPIN(CKU_USER, defaultPIN);
	tcVerifyPIN(CKU_USER, defaultPIN);
	tcVerifyPIN(CKU_USER, defaultPIN);
	tcVerifyPIN(CKU_USER, defaultPIN);

	// Set the Key management PIN to the known value...
	tcVerifyPIN(CKU_SO, pinData);
	if(!tcSetPINSOLoggedIn(CKU_CONTEXT_SPECIFIC,tempPIN))
	{
		memset(pinData,0,TC_PIN_SIZE);
		return CKR_FUNCTION_FAILED;
	}
	// ...so that keys can be erased
	if( tcVerifyPIN(CKU_CONTEXT_SPECIFIC,tempPIN) )
	{
		memset(pinData,0,TC_PIN_SIZE);
		for(i=0;i<TC_NUM_RSA_PRIV_KEYS;i++)
			tcErasePrivateKey(TC_EFTYPE_PRIVKEY + i);
		for(i=0;i<TC_NUM_EC_PRIV_KEYS;i++)
			tcErasePrivateKey(TC_EFTYPE_EC_PRIVKEY + i);
		for(i=0;i<TC_NUM_SECRET_KEYS;i++)
			tcDeleteFile(TC_EFTYPE_SECRET + i);
		for(i=0;i<TC_NUM_FS_OBJS_PER_CLASS;i++)
		{
			tcDeleteFile(TC_EFTYPE_PUBKEY + i);
			tcDeleteFile(TC_EFTYPE_CERT + i);
		}
	}
	else
		status = CKR_FUNCTION_FAILED;

	// Run down the key management PIN retry counter
	tcVerifyPIN(CKU_CONTEXT_SPECIFIC, defaultPIN);
	tcVerifyPIN(CKU_CONTEXT_SPECIFIC, defaultPIN);
	tcVerifyPIN(CKU_CONTEXT_SPECIFIC, defaultPIN);
	tcVerifyPIN(CKU_CONTEXT_SPECIFIC, defaultPIN);

	// De-initialise again
	multosDeselectCurrApplication();
	g_bInitialised = FALSE;

	memset(pinData,0,TC_PIN_SIZE);
	return status;
}

/* C_InitPIN initializes the normal user's PIN (PINREF_G for the WIM app)
 * A session must be open, which implies the MULTOS App is selected.
*/
CK_RV C_InitPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	BYTE pinData[TC_PIN_SIZE];

	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!g_SessionIsOpen[hSession])
		return CKR_SESSION_HANDLE_INVALID;

	if(hSession == 0 || hSession >= MAX_SESSIONS) // Only one session is supported
		return CKR_SESSION_HANDLE_INVALID;

	if(ulPinLen > TC_PIN_SIZE)
		return CKR_PIN_LEN_RANGE;

	if(g_loggedInUser != CKU_SO || !(g_SessionFlags[hSession] & CKF_RW_SESSION))
		return CKR_USER_NOT_LOGGED_IN;

	// Set up given PIN in the format required.
	memset(pinData,0xFF,TC_PIN_SIZE);
	memcpy(pinData,pPin,ulPinLen);

	if(!tcSetPINSOLoggedIn(CKU_USER,pinData))
	{
		memset(pinData,0,TC_PIN_SIZE);
		return CKR_FUNCTION_FAILED;
	}
	memset(pinData,0,TC_PIN_SIZE);
	return CKR_OK;
}


/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV C_SetPIN
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
	BYTE oldPinData[TC_PIN_SIZE];
	BYTE newPinData[TC_PIN_SIZE];
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!g_SessionIsOpen[hSession])
		return CKR_SESSION_HANDLE_INVALID;

	if(hSession == 0 || hSession >= MAX_SESSIONS) // Only one session is supported
		return CKR_SESSION_HANDLE_INVALID;

	if(ulOldLen > TC_PIN_SIZE || ulNewLen > TC_PIN_SIZE)
		return CKR_PIN_LEN_RANGE;

	if(g_loggedInUser == NO_LOGGED_IN_USER || !(g_SessionFlags[hSession] & CKF_RW_SESSION) )
		return CKR_USER_NOT_LOGGED_IN;

	// Set up given PINs in the format required.
	memset(oldPinData,0xFF,TC_PIN_SIZE);
	memcpy(oldPinData,pOldPin,ulOldLen);
	memset(newPinData,0xFF,TC_PIN_SIZE);
	memcpy(newPinData,pNewPin,ulNewLen);

	if(!tcSetPIN(g_loggedInUser,oldPinData,newPinData))
	{
		memset(oldPinData,0,TC_PIN_SIZE);
		memset(newPinData,0,TC_PIN_SIZE);
		return CKR_FUNCTION_FAILED;
	}

	memset(oldPinData,0,TC_PIN_SIZE);
	memset(newPinData,0,TC_PIN_SIZE);
	return CKR_OK;
}

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
CK_RV C_WaitForSlotEvent
(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
)
{
	char msg[64];

	sprintf(msg,"%s tid=%d",__func__,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Multiple slots not supported. Tokens aren't removable so no events to wait for.
	return CKR_NO_EVENT;
}

