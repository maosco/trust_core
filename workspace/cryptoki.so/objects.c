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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <pthread.h>		// For Mutex
#endif
#include <sys/types.h>

// Global variable references
extern CK_BBOOL g_bInitialised;
extern CK_BBOOL g_bDeviceOK;
extern CK_FLAGS g_SessionFlags[];
extern CK_BYTE g_SessionIsOpen[];
extern CK_USER_TYPE g_loggedInUser;

// Local controls
static CK_OBJECT_HANDLE_PTR pObjectArray = NULL;
static CK_ULONG ulObjectArraySize = 0;
static CK_ULONG ulNumMatchedObjects = 0;
static CK_BBOOL bSearchInProgress = FALSE;
static CK_ULONG ulFindIndex = 0;

// ECC session object
static CK_BYTE abPublicKey[160];
static CK_ULONG ulPubKeyLen = 0;
static CK_BYTE abCurve[16];
static CK_ULONG ulCurveLen = 0;

// Lock for critical sections
#ifdef _WIN32
extern HANDLE processLock;
#else
extern pthread_mutex_t processLock;
#endif

static void addObjectToSearchResult(CK_OBJECT_HANDLE hObject)
{
	char msg[64];
	sprintf(msg,"... adding %04x to object list",(WORD)hObject);
	logFunc(msg);
	ulNumMatchedObjects++;

	if(ulNumMatchedObjects > ulObjectArraySize)
	{
		ulObjectArraySize += 10;
		pObjectArray = (CK_OBJECT_HANDLE_PTR) realloc(pObjectArray,ulObjectArraySize*sizeof(CK_OBJECT_HANDLE));
	}
	pObjectArray[ulNumMatchedObjects-1] = hObject;
}

static void fillBigEndianULong(CK_ULONG value, BYTE* buffer)
{
	buffer[0] = value / (256 * 256 * 256);
	buffer[1] = value / (256 * 256);
	buffer[2] = value / 256;
	buffer[3] = value % 256;
}

static CK_ULONG readBigEndianULong(BYTE *buffer)
{
	CK_ULONG v;

	v = buffer[0] * 256 * 256 * 256;
	v += (buffer[1] * 256 * 256);
	v += (buffer[2] * 256);
	v += buffer[3];

	return v;
}

CK_RV C_CreateObject
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
)
{
	int status = 0;
	CK_ULONG i, offset;
	WORD EFid;
	CK_ULONG attrLen;
	CK_ULONG size;
	BYTE *buff;
	CK_ULONG numTemplateAttributes = 0;
	BYTE bCurveID;
	CK_BYTE_PTR pKey;
	CK_BYTE bKeyLen;

	unsigned char abDEROIDp256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
	unsigned char abDEROIDp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
	unsigned char abDEROIDp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!g_bDeviceOK)
		return CKR_DEVICE_REMOVED;

	if(hSession == 0 || hSession >= MAX_SESSIONS)
		return CKR_SESSION_HANDLE_INVALID;

	if(!g_SessionIsOpen[hSession])
		return CKR_SESSION_HANDLE_INVALID;

	if(!(g_SessionFlags[hSession] & CKF_RW_SESSION))
		return CKR_SESSION_READ_ONLY;

	if(phObject == NULL_PTR || pTemplate == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// There must be at least 2 attributes, CKA_CLASS, CKA_TOKEN and other stuff
	if(ulCount < 2)
		return CKR_ARGUMENTS_BAD;

	// There must be a CLASS attribute
	if(pTemplate[0].type != CKA_CLASS)
		return CKR_ARGUMENTS_BAD;


	switch( *(CK_ULONG*)((pTemplate[0].pValue)) )
	{
		case CKO_CERTIFICATE:
			// Check for session objects - not supported
			if(pTemplate[1].type != CKA_TOKEN || *(CK_BYTE*)pTemplate[1].pValue != TRUE)
				return CKR_ARGUMENTS_BAD;

			// Template supported is
			//	CKA_CLASS, CKA_TOKEN, CKA_SUBJECT, CKA_VALUE
			numTemplateAttributes = 4;

			// Attribute count must 4
			if(ulCount != numTemplateAttributes)
				return CKR_TEMPLATE_INCONSISTENT;

			// The last 2 attributes must be CKA_SUBJECT and CKA_VALUE
			if(pTemplate[ulCount-2].type != CKA_SUBJECT || pTemplate[ulCount-1].type != CKA_VALUE)
				return CKR_TEMPLATE_INCONSISTENT;

			// Work out how much space is needed to store object
			size = 2 * (sizeof(CK_ATTRIBUTE_TYPE) + sizeof(CK_ULONG));
			for(i = 2; i < 4; i++)
				size += pTemplate[i].ulValueLen;

			// Try and create a new file with the EFID 53xx - the actual allocated EFID will be the returned object handle
			status = tcCreateEF(0x53,TC_NUM_FS_OBJS_PER_CLASS-1, size,TC_ACCESS_ALWAYS, TC_ACCESS_KEYMAN, &EFid);

			// Return with any appropriate error (if file creation failed)
			if(status != 0)
			{
				switch(status){
				case 1: return CKR_DEVICE_MEMORY;
				case 2: return CKR_USER_NOT_LOGGED_IN;
				default: return CKR_FUNCTION_FAILED;
				}
			}

			// Create buffer to build the object into
			buff = (BYTE*) malloc (size);
			if(!size)
				return CKR_HOST_MEMORY;

			// Concat the attributes together into the buffer
			offset = 0;
			for(i = 2; i < numTemplateAttributes; i++)
			{
				// Attribute type
				fillBigEndianULong(pTemplate[i].type,buff + offset);
				offset += sizeof(CK_ATTRIBUTE_TYPE);

				// Attribute length
				attrLen = pTemplate[i].ulValueLen;
				fillBigEndianULong(attrLen,buff + offset);
				offset += sizeof(CK_ULONG);

				// Attribute value
				memcpy(buff+offset,pTemplate[i].pValue,attrLen);
				offset += attrLen;
			}

			// Write to file
			status = tcWriteEF(EFid,buff,size);

			// Free buffer
			free(buff);

			// If write failed, exit with error
			if(!status)
				return CKR_FUNCTION_FAILED;
			*phObject = EFid;
		break;

		case CKO_PUBLIC_KEY:

			if(pTemplate[1].type != CKA_TOKEN)
				return CKR_ARGUMENTS_BAD;

			// A couple of session objects are supported
			if(*(CK_BYTE*)pTemplate[1].pValue == CK_FALSE)
			{
				if(*((CK_KEY_TYPE*)pTemplate[2].pValue) == CKK_RSA)
				{
					// Used for wrapping the pre-master secret
					// CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE, CKA_MODULUS, CKA_PUBLIC_EXPONENT
					numTemplateAttributes = 5;
					if(ulCount != numTemplateAttributes ||
						pTemplate[2].type != CKA_KEY_TYPE ||
						pTemplate[2].ulValueLen != sizeof(CK_KEY_TYPE) ||
						pTemplate[3].type != CKA_MODULUS ||
						pTemplate[4].type != CKA_PUBLIC_EXPONENT)
						return CKR_TEMPLATE_INCONSISTENT;

					if(!tcLoadUntrustedPublicKey((BYTE*)pTemplate[3].pValue,(WORD)pTemplate[3].ulValueLen,(BYTE*)pTemplate[4].pValue,(WORD)pTemplate[4].ulValueLen))
						return CKR_FUNCTION_FAILED;

					*phObject = RSA_PUBLIC_KEY_SESSION_OBJECT;
				}
				else if(*((CK_KEY_TYPE*)pTemplate[2].pValue) == CKK_EC)
				{
					// Used for ECHDE ephemeral keys and signature verification
					// CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE, CKA_ID, CKA_EC_POINT, CKA_EC_PARAMS, CKA_LABEL
					numTemplateAttributes = 6;
					if(ulCount != numTemplateAttributes ||
						pTemplate[2].type != CKA_KEY_TYPE ||
						pTemplate[2].ulValueLen != sizeof(CK_KEY_TYPE) ||
						pTemplate[3].type != CKA_ID ||
						pTemplate[4].type != CKA_EC_POINT ||
						pTemplate[5].type != CKA_EC_PARAMS
						)
						return CKR_TEMPLATE_INCONSISTENT;

					if(memcmp(pTemplate[5].pValue,abDEROIDp256,pTemplate[5].ulValueLen) == 0)
						bCurveID = TC_NAMED_CURVE_P256;
					else if(memcmp(pTemplate[5].pValue,abDEROIDp384,pTemplate[5].ulValueLen) == 0)
						bCurveID = TC_NAMED_CURVE_P384;
					else if(memcmp(pTemplate[5].pValue,abDEROIDp521,pTemplate[5].ulValueLen) == 0)
						bCurveID = TC_NAMED_CURVE_P521;
					else
						return CKR_TEMPLATE_INCONSISTENT;

					// Validate ECPoint structure
					pKey = (CK_BYTE_PTR)pTemplate[4].pValue;
					if(pKey[0] != 0x04)
						return CKR_TEMPLATE_INCONSISTENT;
					if(pKey[1] == 0x81)
					{
						bKeyLen = pKey[2] - 1;
						pKey += 3;
					}
					else
					{
						bKeyLen = pKey[1] - 1;
						pKey += 2;
					}
					if(*pKey != 0x04)
						return CKR_TEMPLATE_INCONSISTENT;
					pKey ++;

					if(bKeyLen != 64 && bKeyLen != 96 && bKeyLen != 132)
						return CKR_TEMPLATE_INCONSISTENT;

					// Write the extracted public key to MULTOS
					if(!tcLoadUntrustedPublicEccKey(bCurveID,pKey,bKeyLen))
						return CKR_FUNCTION_FAILED;

					// Store original values locally
					ulPubKeyLen = pTemplate[4].ulValueLen;
					if(ulPubKeyLen > sizeof(abPublicKey))
						return CKR_TEMPLATE_INCONSISTENT;
					memcpy(abPublicKey,pTemplate[4].pValue,ulPubKeyLen);

					ulCurveLen = pTemplate[5].ulValueLen;
					if(ulCurveLen > sizeof(abCurve))
						return CKR_TEMPLATE_INCONSISTENT;
					memcpy(abCurve,pTemplate[5].pValue,ulCurveLen);

					// Return object ID
					*phObject = EC_PUBLIC_KEY_SESSION_OBJECT;
				}
			}
			else
			{
				// TOKEN object template. Check against supported templates

				//	RSA: CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE, CKA_ID, CKA_SUBJECT, CKA_ENCRYPT, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_LABEL
				//	ECC: CKA_CLASS, CKA_TOKEN, CKA_KEY_TYPE, CKA_ID, CKA_SUBJECT, CKA_ENCRYPT, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKA_EC_POINT, CKA_EC_PARAMS, CKA_LABEL
				if(pTemplate[2].type != CKA_KEY_TYPE || pTemplate[2].ulValueLen != sizeof(CK_KEY_TYPE) )
					return CKR_TEMPLATE_INCONSISTENT;

				// RSA and ECC only
				if(*((CK_KEY_TYPE*)pTemplate[2].pValue) == CKK_RSA)
					numTemplateAttributes = 13;
				else if (*((CK_KEY_TYPE*)pTemplate[2].pValue) == CKK_EC)
					numTemplateAttributes = 12;
				else
					return CKR_TEMPLATE_INCONSISTENT;

				// Common parts of template
				if(ulCount != numTemplateAttributes ||
					pTemplate[3].type != CKA_ID ||
					pTemplate[4].type != CKA_SUBJECT ||
					pTemplate[5].type != CKA_ENCRYPT ||
					pTemplate[5].ulValueLen != sizeof(CK_BBOOL) ||
					pTemplate[6].type != CKA_VERIFY ||
					pTemplate[6].ulValueLen != sizeof(CK_BBOOL) ||
					pTemplate[7].type != CKA_VERIFY_RECOVER ||
					pTemplate[7].ulValueLen != sizeof(CK_BBOOL) ||
					pTemplate[8].type != CKA_WRAP ||
					pTemplate[8].ulValueLen != sizeof(CK_BBOOL))
					return CKR_TEMPLATE_INCONSISTENT;

				// RSA specific
				if(*((CK_KEY_TYPE*)pTemplate[2].pValue) == CKK_RSA)
				{
					if (pTemplate[9].type != CKA_MODULUS ||
					pTemplate[10].type != CKA_MODULUS_BITS ||
					pTemplate[11].type != CKA_PUBLIC_EXPONENT ||
					pTemplate[12].type != CKA_LABEL)
					return CKR_TEMPLATE_INCONSISTENT;
				}
				// ECC specific
				else
				{
					if (pTemplate[9].type != CKA_EC_POINT ||
					pTemplate[10].type != CKA_EC_PARAMS ||
					pTemplate[11].type != CKA_LABEL)
					return CKR_TEMPLATE_INCONSISTENT;
				}

				// Work out how much space is needed to store object
				size = (numTemplateAttributes-2) * (sizeof(CK_ATTRIBUTE_TYPE) + sizeof(CK_ULONG));
				for(i = 2; i < numTemplateAttributes; i++)
					size += pTemplate[i].ulValueLen;

				// Create buffer to build the object into
				buff = (BYTE*) malloc (size);
				if(!buff)
					return CKR_HOST_MEMORY;

				// Concat the attributes together into the buffer
				offset = 0;
				for(i = 2; i < numTemplateAttributes; i++)
				{
					// Attribute type
					fillBigEndianULong(pTemplate[i].type,buff + offset);
					offset += sizeof(CK_ATTRIBUTE_TYPE);

					// Attribute length
					attrLen = pTemplate[i].ulValueLen;
					fillBigEndianULong(attrLen,buff + offset);
					offset += sizeof(CK_ULONG);

					// Attribute value
					memcpy(buff+offset,pTemplate[i].pValue,attrLen);
					offset += attrLen;
				}

				// Try and create a new file with the EFID 60xx - the actual allocated EFID will be the returned object handle
				// As a key object, this MULTOS implementation requires PIN-K to update the file
				status = tcCreateEF(0x60, TC_NUM_FS_OBJS_PER_CLASS-1, size,TC_ACCESS_ALWAYS, TC_ACCESS_KEYMAN, &EFid);

				// Return with any appropriate error (if file creation failed)
				if(status != 0)
				{
					switch(status){
					case 1: return CKR_DEVICE_MEMORY;
					case 2: return CKR_USER_NOT_LOGGED_IN;
					default: return CKR_FUNCTION_FAILED;
					}
				}

				// Write to file
				status = tcWriteEF(EFid,buff,size);

				// Free buffer
				free(buff);

				// If write failed, exit with error
				if(!status)
					return CKR_FUNCTION_FAILED;
				*phObject = EFid;
			}
			break;

		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return CKR_OK;

}

CK_RV C_CopyObject
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_OBJECT_HANDLE     hObject,     /* the object's handle */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
  CK_ULONG             ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
	char msg[64];

	sprintf(msg,"%s (%d)",__func__,(int)hSession);
	logFunc(msg);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
	WORD wSize;
	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!g_bDeviceOK)
		return CKR_DEVICE_REMOVED;

	if(hSession == 0 || hSession >= MAX_SESSIONS)
		return CKR_SESSION_HANDLE_INVALID;

	if(!g_SessionIsOpen[hSession])
		return CKR_SESSION_HANDLE_INVALID;

	if(!(g_SessionFlags[hSession] & CKF_RW_SESSION))
		return CKR_SESSION_READ_ONLY;

	// If it is the RSA public key session object
	if(hObject == RSA_PUBLIC_KEY_SESSION_OBJECT)
	{
		// Overwrite existing value
		if(tcLoadUntrustedPublicKey((BYTE*)msg,0,(BYTE*)msg,0))
			return CKR_OK;
		else
			return CKR_FUNCTION_FAILED;
	}

	// If it is the EC session key
	if(hObject == EC_PUBLIC_KEY_SESSION_OBJECT)
	{
		// Erase local objects
		memset(abCurve,0,sizeof(abCurve));
		memset(abPublicKey,0,sizeof(abPublicKey));
		ulCurveLen = 0;
		ulPubKeyLen = 0;
		return CKR_OK;
	}

	// See if file exists before trying to delete it
	if(tcSelectEF(hObject,&wSize))
		if(tcDeleteFile((WORD)hObject))
			return CKR_OK;
		else
			return CKR_FUNCTION_FAILED;
	else
	{
		return CKR_OBJECT_HANDLE_INVALID;
	}
}

CK_RV C_GetObjectSize
(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(pulSize == NULL)
		return CKR_ARGUMENTS_BAD;
	*pulSize = 0;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

//TODO: Cache the object data in case a different attribute is requested from the same object next time.
/* C_GetAttributeValue obtains the value of one or more object
 * attributes. */
CK_RV C_GetAttributeValue
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	WORD fileSize;
	WORD  bytesRead;
	BYTE *data = NULL;
	CK_ULONG i,offset;
	WORD fileType;
	CK_ATTRIBUTE_TYPE currAttribute;
	CK_ULONG currAttribLen;
	BYTE found;
	BYTE tempBuffer[256];
	CK_RV status = CKR_OK;
	TC_SECRET_KEY_ATTRS secretAttrs;
	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(!bSearchInProgress)
#ifdef _WIN32
		WaitForSingleObject(processLock,INFINITE);
#else
		pthread_mutex_lock(&processLock);
#endif

	if(!g_bInitialised)
		status =  CKR_CRYPTOKI_NOT_INITIALIZED;

	else if(!g_bDeviceOK)
		status =  CKR_DEVICE_REMOVED;

	else if(hSession > MAX_SESSIONS)
		status =  CKR_SESSION_HANDLE_INVALID;

	else if(!g_SessionIsOpen[hSession])
		status =  CKR_SESSION_HANDLE_INVALID;

	if(status != CKR_OK)
	{
		if(!bSearchInProgress)
#ifdef _WIN32
			ReleaseMutex(processLock);
#else
			pthread_mutex_unlock(&processLock);
#endif
		return status;
	}

	// Get the type of file from the handle (which is the EFid)
	fileType = (WORD)hObject & 0xFF00;

	// Objects in the file app need to be selected
	found = 0;
	if(hObject == EC_PUBLIC_KEY_SESSION_OBJECT)
		found = 1;
	else if(fileType == TC_EFTYPE_CERT || fileType == TC_EFTYPE_PUBKEY)
		found = tcSelectEF((WORD)hObject,&fileSize);
	else if (fileType == TC_EFTYPE_PRIVKEY && (hObject & 0x00FF) < TC_NUM_RSA_PRIV_KEYS)
		found = 1;
	else if (fileType == TC_EFTYPE_EC_PRIVKEY && (hObject & 0x00FF) < TC_NUM_EC_PRIV_KEYS)
		found = 1;
	else if (fileType == TC_EFTYPE_SECRET)
		found = tcReadSecretKeyAttrs(hObject,&secretAttrs);

	if(found)
	{
		// For each attribute in the template
		for(i = 0; i < ulCount; i++)
		{
			// Some attributes are special. The rest can be searched for in the data blob.
			if( pTemplate[i].type == CKA_CLASS )
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
					continue;
				}
				if( pTemplate[i].ulValueLen != sizeof(CK_OBJECT_CLASS))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}

				switch(fileType)
				{
					case (TC_EFTYPE_CERT): *(CK_ULONG*)((pTemplate[i].pValue)) = CKO_CERTIFICATE;
						break;
					case (TC_EFTYPE_PUBKEY): *(CK_ULONG*)((pTemplate[i].pValue)) = CKO_PUBLIC_KEY;
						break;
					case (TC_EFTYPE_PRIVKEY):
					case (TC_EFTYPE_EC_PRIVKEY):
							*(CK_ULONG*)((pTemplate[i].pValue)) = CKO_PRIVATE_KEY;
						break;
					case (TC_EFTYPE_SECRET): *(CK_ULONG*)((pTemplate[i].pValue)) = CKO_SECRET_KEY;
						break;
					default:
						pTemplate[i].ulValueLen = -1;
						break;
				}
			}
			else if (pTemplate[i].type == CKA_TOKEN)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = sizeof(CK_BYTE);
					continue;
				}
				if( pTemplate[i].ulValueLen != sizeof(CK_BYTE))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}

				if ((WORD)hObject == RSA_PUBLIC_KEY_SESSION_OBJECT || (WORD)hObject == EC_PUBLIC_KEY_SESSION_OBJECT)
					*(CK_BYTE*)pTemplate[1].pValue = CK_FALSE;
				else
					*(CK_BYTE*)pTemplate[1].pValue = CK_TRUE;
			}
			else if (pTemplate[i].type == CKA_KEY_TYPE && fileType != TC_EFTYPE_PUBKEY)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
					continue;
				}
				if( pTemplate[i].ulValueLen != sizeof(CK_KEY_TYPE))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}

				switch(fileType)
				{
					case (TC_EFTYPE_PRIVKEY): *(CK_KEY_TYPE*)((pTemplate[i].pValue)) = CKK_RSA;
						break;
					case (TC_EFTYPE_EC_PRIVKEY): *(CK_KEY_TYPE*)((pTemplate[i].pValue)) = CKK_EC;
						break;
					case (TC_EFTYPE_SECRET):
							if(secretAttrs.bKeyType == TC_KEYTYPE_AES)
								*(CK_KEY_TYPE*)((pTemplate[i].pValue)) = CKK_AES;
							else
								*(CK_KEY_TYPE*)((pTemplate[i].pValue)) = CKK_GENERIC_SECRET;
						break;
					default:
						*(CK_ULONG*)((pTemplate[i].pValue)) = CKK_VENDOR_DEFINED;
						break;
				}
			}
			else if (pTemplate[i].type == CKA_MODULUS && fileType == TC_EFTYPE_PRIVKEY)
			{
				if(pTemplate[i].pValue != NULL)
					// Call WIM function to get the public key from the private key value and put it into the provided buffer
					pTemplate[i].ulValueLen = tcReadRsaModulus((WORD)hObject,(BYTE*)pTemplate[i].pValue, (WORD)pTemplate[i].ulValueLen);
				else
				{
					// Use a temporary buffer to get the modulus so that we can set the length in the reply
					pTemplate[i].ulValueLen = tcReadRsaModulus((WORD)hObject,tempBuffer, sizeof(tempBuffer));
				}
			}
			else if (fileType == TC_EFTYPE_PRIVKEY && pTemplate[i].type == CKA_LABEL)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = 4;
					continue;
				}
				if( pTemplate[i].ulValueLen < 4)
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}

				if(hObject == TC_EF_PRIVKEY_1)
					memcpy(pTemplate[i].pValue,"KEY0",4);
				else
					memcpy(pTemplate[i].pValue,"KEY1",4);
			}
			else if (fileType == TC_EFTYPE_EC_PRIVKEY && pTemplate[i].type == CKA_LABEL)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = 6;
					continue;
				}
				if( pTemplate[i].ulValueLen < 6)
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}

				sprintf((char*)pTemplate[i].pValue,"ECKEY%d", (int)(hObject & 0xFF));
			}
			else if (fileType == TC_EFTYPE_SECRET && pTemplate[i].type == CKA_LABEL)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = strlen(secretAttrs.acLabel);
					continue;
				}
				if( pTemplate[i].ulValueLen < strlen(secretAttrs.acLabel))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				memcpy(pTemplate[i].pValue,secretAttrs.acLabel,pTemplate[i].ulValueLen);
			}
			else if (fileType == TC_EFTYPE_SECRET && pTemplate[i].type == CKA_VALUE_LEN)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = sizeof(CK_ULONG);
					continue;
				}
				if( pTemplate[i].ulValueLen != sizeof(CK_ULONG))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				*(CK_ULONG*)((pTemplate[i].pValue)) = secretAttrs.bKeyLen;
			}
			else if (fileType == TC_EFTYPE_SECRET && pTemplate[i].type == CKA_CHECK_VALUE)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = 3;
					continue;
				}
				if( pTemplate[i].ulValueLen != 3)
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				memcpy(pTemplate[i].pValue,secretAttrs.abKcv,pTemplate[i].ulValueLen);
			}
			else if (fileType == TC_EFTYPE_SECRET &&		//Secret key file flags
					(pTemplate[i].type == CKA_EXTRACTABLE || pTemplate[i].type == CKA_ENCRYPT || pTemplate[i].type == CKA_DECRYPT ||
							pTemplate[i].type == CKA_WRAP || pTemplate[i].type == CKA_UNWRAP))
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = sizeof(CK_BYTE);
					continue;
				}
				if( pTemplate[i].ulValueLen != sizeof(CK_BYTE))
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				switch(pTemplate[i].type)
				{
					case CKA_EXTRACTABLE: *((CK_BYTE*)(pTemplate[i].pValue)) = ((secretAttrs.wAttrs & TC_ATTR_EXTRACT) == TC_ATTR_EXTRACT); break;
					case CKA_ENCRYPT: *((CK_BYTE*)(pTemplate[i].pValue)) = ((secretAttrs.wAttrs & TC_ATTR_ENCRYPT) == TC_ATTR_ENCRYPT); break;
					case CKA_DECRYPT: *((CK_BYTE*)(pTemplate[i].pValue)) = ((secretAttrs.wAttrs & TC_ATTR_DECRYPT) == TC_ATTR_DECRYPT); break;
					case CKA_WRAP: *((CK_BYTE*)(pTemplate[i].pValue)) = ((secretAttrs.wAttrs & TC_ATTR_WRAP) == TC_ATTR_WRAP); break;
					case CKA_UNWRAP: *((CK_BYTE*)(pTemplate[i].pValue)) = ((secretAttrs.wAttrs & TC_ATTR_UNWRAP) == TC_ATTR_UNWRAP); break;
					//case CKA_LOCAL: *((CK_BYTE*)(pTemplate[i].pValue)) = CK_TRUE; break;	//TODO: For now don't support. LOCAL is for keys generated internally only. Need to add something for that
					default: pTemplate[i].ulValueLen = -1; // Should never get here.
				}
			}
			else if (hObject == EC_PUBLIC_KEY_SESSION_OBJECT && pTemplate[i].type == CKA_EC_POINT)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = ulPubKeyLen;
					continue;
				}
				if( pTemplate[i].ulValueLen != ulPubKeyLen)
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				memcpy(pTemplate[i].pValue,abPublicKey,ulPubKeyLen);
			}
			else if (hObject == EC_PUBLIC_KEY_SESSION_OBJECT && pTemplate[i].type == CKA_EC_PARAMS)
			{
				if( pTemplate[i].pValue == NULL)
				{
					pTemplate[i].ulValueLen = ulCurveLen;
					continue;
				}
				if( pTemplate[i].ulValueLen != ulCurveLen)
				{
					pTemplate[i].ulValueLen = -1;
					continue;
				}
				memcpy(pTemplate[i].pValue,abCurve,ulCurveLen);
			}
			else
			{
				// Try and read the data
				if(data == NULL)
				{
					data = (BYTE*) malloc (fileSize);
					if(!data)
					{
						if(!bSearchInProgress)
#ifdef _WIN32
							ReleaseMutex(processLock);
#else
							pthread_mutex_unlock(&processLock);
#endif
						return CKR_HOST_MEMORY;
					}
					bytesRead = tcReadCurrentEF(0,fileSize,data);
				}

				// Search data blob
				offset = 0;
				found = 0;
				while( offset < bytesRead && !found )
				{
					currAttribute = readBigEndianULong(data+offset);
					offset += sizeof(CK_ULONG);
					currAttribLen = readBigEndianULong(data+offset);
					offset += sizeof(CK_ULONG);

					if(pTemplate[i].type == currAttribute)
					{
						if(pTemplate[i].pValue == NULL)
							pTemplate[i].ulValueLen = currAttribLen;
						else if (pTemplate[i].ulValueLen >= currAttribLen)
							memcpy(pTemplate[i].pValue,data+offset,currAttribLen);
						found = 1;
					}

					// Skip over data
					offset += currAttribLen;
				}
				if(!found)
					pTemplate[i].ulValueLen = -1;
			}
		}
		if(data)
			free(data);
		if(!bSearchInProgress)
#ifdef _WIN32
			ReleaseMutex(processLock);
#else
			pthread_mutex_unlock(&processLock);
#endif
		return CKR_OK;
	}
	else
	{
		if(!bSearchInProgress)
#ifdef _WIN32
			ReleaseMutex(processLock);
#else
			pthread_mutex_unlock(&processLock);
#endif
		return CKR_OBJECT_HANDLE_INVALID;
	}
}

/* C_SetAttributeValue modifies the value of one or more object
 * attributes */
CK_RV C_SetAttributeValue
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
)
{
	WORD fileSize;
	CK_ULONG i,offset;
	WORD fileType;
	BYTE *data;
	CK_ULONG bytesRead;
	CK_ATTRIBUTE_TYPE currAttribute;
	CK_ULONG currAttribLen;
	BYTE found;

	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);


	if(!g_bInitialised)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if(!g_bDeviceOK)
		return CKR_DEVICE_REMOVED;

	if(hSession == 0 || hSession >= MAX_SESSIONS)
		return CKR_SESSION_HANDLE_INVALID;

	if(!g_SessionIsOpen[hSession])
		return CKR_SESSION_HANDLE_INVALID;

	if(!(g_SessionFlags[hSession] & CKF_RW_SESSION))
		return CKR_SESSION_READ_ONLY;

	if(g_loggedInUser == NO_LOGGED_IN_USER)
		return CKR_USER_NOT_LOGGED_IN;

	// Get the type of file from the handle (which is the EFid)
	fileType = (WORD)hObject & 0xFF00;

	// Private key and secret key files don't have attributes you can update
	if (fileType == TC_EFTYPE_PRIVKEY || fileType == TC_EFTYPE_SECRET)
		return CKR_ATTRIBUTE_READ_ONLY;

	// For each attribute in the update template
	for (i = 0; i < ulCount; i++)
	{
		// Check if we allow it to be updated
		if(fileType == TC_EFTYPE_PUBKEY)
		{
			switch(pTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
				case CKA_KEY_TYPE:
				case CKA_MODULUS:
				case CKA_MODULUS_BITS:
				case CKA_PUBLIC_EXPONENT:
				case CKA_EC_PARAMS:
				case CKA_EC_POINT:
					return CKR_ATTRIBUTE_READ_ONLY;

				case CKA_ID:
					// No validation to do.
					break;

				case CKA_SUBJECT:
				case CKA_ENCRYPT:
				case CKA_VERIFY:
				case CKA_VERIFY_RECOVER:
				case CKA_WRAP:
					// These should all be boolean values
					currAttribLen = pTemplate[i].ulValueLen;
					if(currAttribLen != 1 || (*((CK_BBOOL*)pTemplate[i].pValue) != TRUE && *((CK_BBOOL*)pTemplate[i].pValue) != FALSE ))
						return CKR_ATTRIBUTE_VALUE_INVALID;
					break;

				default:
					return CKR_TEMPLATE_INCONSISTENT;
			}
		}
		else if (fileType == TC_EFTYPE_CERT)
		{
			switch(pTemplate[i].type)
			{
				case CKA_CLASS:
				case CKA_TOKEN:
					return CKR_ATTRIBUTE_READ_ONLY;

				case CKA_SUBJECT:
				case CKA_VALUE:
					// These are all OK
					break;

				default:
					return CKR_TEMPLATE_INCONSISTENT;
			}
		}
		else
		{
			// Unsupported object type
			return CKR_OBJECT_HANDLE_INVALID;
		}
	}

	// Select the EF that holds the object
	if(tcSelectEF((WORD)hObject,&fileSize))
	{
		// Read its data so that we can parse it to get its data layout
		data = (BYTE*) malloc (fileSize);
		if(!data)
			return CKR_HOST_MEMORY;
		bytesRead = tcReadCurrentEF(0,fileSize,data);

		// For each attribute in the update template
		for (i = 0; i < ulCount; i++)
		{
			// Search for it in the data
			offset = 0;
			found = 0;
			while( offset < bytesRead && !found )
			{
				currAttribute = readBigEndianULong(data+offset);
				offset += sizeof(CK_ULONG);
				currAttribLen = readBigEndianULong(data+offset);
				offset += sizeof(CK_ULONG);

				if(pTemplate[i].type == currAttribute)
				{
					// Value found
					found = 1;

					// Only allow updates where the data is the same size
					if(currAttribLen != pTemplate[i].ulValueLen)
					{
						free(data);
						return CKR_ATTRIBUTE_VALUE_INVALID;
					}

					// Write the updated data
					if( !tcWriteCurrentEF(offset,(WORD)pTemplate[i].ulValueLen,(BYTE*)pTemplate[i].pValue) )
					{
						free(data);
						return CKR_FUNCTION_FAILED;
					}
				}

				// Skip over data
				offset += currAttribLen;
			}

			// Trap the hopefully impossible case that the attribute wasn't found!
			if(!found)
			{
				free(data);
				return CKR_GENERAL_ERROR;
			}
		}
		free(data);
		return CKR_OK;
	}
	else
	{
		return CKR_OBJECT_HANDLE_INVALID;
	}
}

// This is for EFs stored in the file app
static int compareCurrentEFToTemplate(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulCount, WORD fileSize)
{
	BYTE *data;
	int bytesRead;
	CK_ULONG matchesFound = 0;
	CK_ULONG i;
	int offset,found;
	CK_ATTRIBUTE_TYPE currAttributeType;
	CK_ULONG currAttributeLen;

	// Read file's data so that we can parse it to get its data layout
	data = (BYTE*) malloc (fileSize);
	if(!data)
		return 0;

	bytesRead = tcReadCurrentEF(0,fileSize,data);
	//sprintf(msg,"Read %d, attrcount %d",bytesRead,ulCount);
	//logFunc(msg);
	if(bytesRead)
	{
		// For each attribute in the template
		for(i = 0; i < ulCount; i++)
		{
			//sprintf(msg,"Template attribute type = 0x%x",pTemplate[i].type);
			//logFunc(msg);
			//if(pTemplate[i].type == CKA_LABEL)
			//	logFunc((char*)pTemplate[i].pValue);

			// Count CKA_CLASS and CKA_TOKEN as matches
			if(pTemplate[i].type == CKA_CLASS || pTemplate[i].type == CKA_TOKEN)
			{
				//logFunc("CLASS or TOKEN attribute type match");
				matchesFound++;
			}
			else
			{
				// Otherwise see if it is in the file data with the same value
				// TODO: This is the third time this block of code has appeared in one form or another. Refactor it?
				offset = 0;
				found = 0;
				while( offset >= 0 && offset < bytesRead && !found )
				{
					currAttributeType = readBigEndianULong(data + offset);
					offset += sizeof (CK_ATTRIBUTE_TYPE);
					currAttributeLen = readBigEndianULong(data + offset);
					offset += sizeof (CK_ULONG);

					//sprintf(msg,"Current attribute type,len = 0x%x %d",currAttributeType,currAttributeLen);
					//logFunc(msg);

					if(pTemplate[i].type == currAttributeType)
					{
						// Value found
						found = 1;

						// Does its value match?
						if(pTemplate[i].ulValueLen == currAttributeLen && memcmp(data+offset,pTemplate[i].pValue,currAttributeLen) == 0)
						{
							//logFunc("...matched");
							matchesFound++;
						}
					}
					offset += currAttributeLen;
				}
			}
		}
	}
	free(data);

	return matchesFound == ulCount;
}

static CK_BBOOL attrsSet(TC_SECRET_KEY_ATTRS *pSecretKeyAttrs,WORD wAttrs)
{
	return (pSecretKeyAttrs->wAttrs & wAttrs) == wAttrs;
}

// For secret key files
static int compareSecretKeyAttrsToTemplate(CK_ATTRIBUTE_PTR pTemplate,CK_ULONG ulCount, TC_SECRET_KEY_ATTRS *pSecretKeyAttrs)
{
	CK_ULONG i;
	int lenToCompare = 0;
	CK_ULONG ulVal = 0;
	CK_ULONG matchesFound = 0;

	// For each attribute in the template
	for(i = 0; i < ulCount; i++)
	{
		// See if the value given matches the value in the object.
		switch(pTemplate[i].type)
		{
			case CKA_CLASS:	// Fixed value is CKO_SECRET_KEY
				if(pTemplate[i].ulValueLen == sizeof(CK_ULONG) && *(CK_ULONG*)(pTemplate[i].pValue) == CKO_SECRET_KEY)
					matchesFound++;
				break;

			case CKA_TOKEN: // Fixed value is CK_TRUE
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == CK_TRUE)
					matchesFound++;
				break;

			case CKA_LOCAL:	// Fixed value is CK_TRUE
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == CK_TRUE)
					matchesFound++;
				break;

			case CKA_LABEL:
				lenToCompare = pTemplate[i].ulValueLen > TC_SECRET_KEY_LABEL_LEN ? TC_SECRET_KEY_LABEL_LEN : pTemplate[i].ulValueLen;
				if(strncmp((const char*)pTemplate[i].pValue,pSecretKeyAttrs->acLabel,lenToCompare) == 0)
					matchesFound++;
				break;

			case CKA_KEY_TYPE:
				if(pTemplate[i].ulValueLen == sizeof(CK_ULONG))
				{
					ulVal = *(CK_ULONG*)(pTemplate[i].pValue);
					if( (ulVal == CKK_GENERIC_SECRET && (pSecretKeyAttrs->bKeyType == TC_KEYTYPE_MS || pSecretKeyAttrs->bKeyType == TC_KEYTYPE_PMS)) ||
						(ulVal == CKK_AES && pSecretKeyAttrs->bKeyType == TC_KEYTYPE_AES))
						matchesFound++;
				}
				break;

			case CKA_VALUE_LEN:
				if(pTemplate[i].ulValueLen == sizeof(CK_ULONG))
				{
					ulVal = *(CK_ULONG*)(pTemplate[i].pValue);
					if(ulVal == (CK_LONG)pSecretKeyAttrs->bKeyLen)
						matchesFound++;
				}
				break;

			case CKA_ENCRYPT:
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == attrsSet(pSecretKeyAttrs,TC_ATTR_ENCRYPT))
					matchesFound++;
				break;

			case CKA_DECRYPT:
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == attrsSet(pSecretKeyAttrs,TC_ATTR_DECRYPT))
					matchesFound++;
				break;

			case CKA_EXTRACTABLE:
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == attrsSet(pSecretKeyAttrs,TC_ATTR_EXTRACT))
					matchesFound++;
				break;

			case CKA_WRAP:
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == attrsSet(pSecretKeyAttrs,TC_ATTR_WRAP))
					matchesFound++;
				break;

			case CKA_UNWRAP:
				if(pTemplate[i].ulValueLen == sizeof(CK_BBOOL) && *(CK_BBOOL*)(pTemplate[i].pValue) == attrsSet(pSecretKeyAttrs,TC_ATTR_UNWRAP))
					matchesFound++;
				break;
		}

	}
	return matchesFound == ulCount;
}

/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_RV C_FindObjectsInit
(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
)
{
	CK_ULONG i;
	CK_BBOOL bSearchCerts = FALSE;
	CK_BBOOL bSearchPubKeys = FALSE;
	CK_BBOOL bSearchPrivKeys = FALSE;
	CK_BBOOL bSearchSecretKeys = FALSE;
	TC_SECRET_KEY_ATTRS sSecretKeyAttrs;
	WORD EFId;
	WORD fileSize;
	CK_RV status = CKR_OK;
	CK_BYTE bIdx;
	char msg[64];

#ifdef _WIN32
	WaitForSingleObject(processLock,INFINITE);
#else
	pthread_mutex_lock(&processLock);
#endif

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		status = CKR_CRYPTOKI_NOT_INITIALIZED;

	else if(!g_bDeviceOK)
		status = CKR_DEVICE_REMOVED;

	else if(hSession == 0 || hSession >= MAX_SESSIONS)
		status = CKR_SESSION_HANDLE_INVALID;

	else if(!g_SessionIsOpen[hSession])
		status = CKR_SESSION_HANDLE_INVALID;

	if(status != CKR_OK)
	{
#ifdef _WIN32
		ReleaseMutex(processLock);
#else
		pthread_mutex_unlock(&processLock);
#endif
		return status;
	}

	// Initialise
	ulNumMatchedObjects = 0;
	ulFindIndex = 0;

	// A template size of 0 means "search everything"
	if(ulCount == 0)
	{
		bSearchCerts = TRUE;
		bSearchPubKeys = TRUE;
		bSearchPrivKeys = TRUE;
		bSearchSecretKeys = TRUE;
	}
	else // Parse search template to see if a class is specified.
	{
		if(pTemplate == NULL)
			return CKR_ARGUMENTS_BAD;

		for(i = 0; i < ulCount; i++)
		{
			if(pTemplate[i].type == CKA_CLASS)
			{
				if(*(CK_ULONG*)((pTemplate[i].pValue)) == CKO_CERTIFICATE)
				{
					bSearchCerts = TRUE;
					break;
				}
				else if(*(CK_ULONG*)((pTemplate[i].pValue)) == CKO_PRIVATE_KEY)
				{
					bSearchPrivKeys = TRUE;
					break;
				}
				else if(*(CK_ULONG*)((pTemplate[i].pValue)) == CKO_PUBLIC_KEY)
				{
					bSearchPubKeys = TRUE;
					break;
				}
				else if(*(CK_ULONG*)((pTemplate[i].pValue)) == CKO_SECRET_KEY)
				{
					bSearchSecretKeys = TRUE;
					break;
				}
				else
					return CKR_ATTRIBUTE_VALUE_INVALID;
			}
		}
	}

	// Do the actual search.
	if(bSearchCerts)
	{
		// Try selecting every possible cert EFID
		for(EFId = TC_EFTYPE_CERT; EFId <= TC_EFTYPE_CERT+TC_NUM_FS_OBJS_PER_CLASS; EFId++)
		{
			if(tcSelectEF(EFId,&fileSize))
			{
				if(ulCount == 0 || (ulCount == 1 && pTemplate[0].type == CKA_CLASS) || compareCurrentEFToTemplate(pTemplate,ulCount,fileSize) )
					addObjectToSearchResult(EFId);
			}
		}
	}

	if(bSearchPubKeys)
	{
		// Try selecting every possible pub key EFID
		for(EFId = TC_EFTYPE_PUBKEY; EFId <= TC_EFTYPE_PUBKEY+TC_NUM_FS_OBJS_PER_CLASS; EFId++)
		{
			if(tcSelectEF(EFId,&fileSize))
				if(ulCount == 0 || (ulCount == 1 && pTemplate[0].type == CKA_CLASS) || compareCurrentEFToTemplate(pTemplate,ulCount,fileSize) )
					addObjectToSearchResult(EFId);
		}
	}

	if(bSearchPrivKeys && g_loggedInUser != NO_LOGGED_IN_USER)
	{
		// These don't have attributes, so just include them all
		for(bIdx = 0; bIdx < TC_NUM_RSA_PRIV_KEYS;bIdx++)
			addObjectToSearchResult(TC_EFTYPE_PRIVKEY + bIdx);

		for(bIdx = 0; bIdx < TC_NUM_EC_PRIV_KEYS;bIdx++)
			addObjectToSearchResult(TC_EFTYPE_EC_PRIVKEY + bIdx);
	}

	if(bSearchSecretKeys && g_loggedInUser != NO_LOGGED_IN_USER)
	{
		// Try getting the info for every possible secret key EFID
		for(EFId = TC_EFTYPE_SECRET; EFId <= TC_EFTYPE_SECRET+TC_NUM_SECRET_KEYS; EFId++)
		{
			if(tcReadSecretKeyAttrs(EFId,&sSecretKeyAttrs))
				if(ulCount == 0 || compareSecretKeyAttrsToTemplate(pTemplate,ulCount,&sSecretKeyAttrs) )
					addObjectToSearchResult(EFId);
		}
	}
	bSearchInProgress = TRUE;
	return CKR_OK;
}

/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_RV C_FindObjects
(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	CK_ULONG i;
	char msg[64];
	CK_RV status = CKR_OK;

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(phObject == NULL || pulObjectCount == NULL)
	{
		status = CKR_ARGUMENTS_BAD;
		logFunc("...args bad");
	}

	if(status == CKR_OK)
	{
		*pulObjectCount = 0;

		if(!g_bInitialised)
		{
			logFunc("...not initialised");
			status = CKR_CRYPTOKI_NOT_INITIALIZED;
		}
		else if(!g_bDeviceOK)
		{
			logFunc("...device removed");
			status = CKR_DEVICE_REMOVED;
		}
		else if(hSession == 0 || hSession >= MAX_SESSIONS)
		{
			sprintf(msg,"...invalid handle (%d)",(int)hSession);
			logFunc(msg);
			status = CKR_SESSION_HANDLE_INVALID;
		}
		else if(!g_SessionIsOpen[hSession])
		{
			sprintf(msg,"...invalid session (%d)",(int)hSession);
			logFunc(msg);
			status = CKR_SESSION_HANDLE_INVALID;
		}
		else if(!bSearchInProgress)
		{
			logFunc("...search not intialised");
			status = CKR_OPERATION_NOT_INITIALIZED;
		}
		if(status == CKR_OK)
		{
			// Work out how many objects we can actually return
			if(ulMaxObjectCount <= (ulNumMatchedObjects - ulFindIndex))
				*pulObjectCount = ulMaxObjectCount;
			else
				*pulObjectCount = ulNumMatchedObjects - ulFindIndex;

			// Return that many objects
			for(i = 0; i < *pulObjectCount; i++)
				phObject[i] = pObjectArray[ulFindIndex+i];

			// Update the index
			ulFindIndex += *pulObjectCount;

			sprintf(msg,"...ok (%d objects returned)",(int)*pulObjectCount);
			logFunc(msg);
		}
	}

	if(status != CKR_OK)
#ifdef _WIN32
		ReleaseMutex(processLock);
#else
		pthread_mutex_unlock(&processLock);
#endif

	return status;
}

/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_RV C_FindObjectsFinal
(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CK_RV status = CKR_OK;
	char msg[64];

	sprintf(msg,"%s (%d) tid=%d",__func__,(int)hSession,(int)gettid());
	logFunc(msg);

	if(!g_bInitialised)
		status = CKR_CRYPTOKI_NOT_INITIALIZED;

	else if(!g_bDeviceOK)
		status = CKR_DEVICE_REMOVED;

	else if(hSession == 0 || hSession >= MAX_SESSIONS)
		status = CKR_SESSION_HANDLE_INVALID;

	else if(!g_SessionIsOpen[hSession])
		status = CKR_SESSION_HANDLE_INVALID;

	else if(!bSearchInProgress)
		status = CKR_OPERATION_NOT_INITIALIZED;

	if(status == CKR_OK)
	{
		// Close the search
		bSearchInProgress = FALSE;
		ulNumMatchedObjects = 0;
	}

#ifdef _WIN32
	ReleaseMutex(processLock);
#else
	pthread_mutex_unlock(&processLock);
#endif

	return status;
}
