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

// Locals
static BYTE abDEROIDp256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static BYTE abDEROIDp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static BYTE abDEROIDp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

#define COMMON_CHECKS() \
	if(!g_bInitialised) \
		return CKR_CRYPTOKI_NOT_INITIALIZED; \
	if(!g_bDeviceOK) \
		return CKR_DEVICE_REMOVED; \
	if(hSession == 0 || hSession >= MAX_SESSIONS) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(!g_SessionIsOpen[hSession]) \
		return CKR_SESSION_HANDLE_INVALID; \
	if(g_loggedInUser == NO_LOGGED_IN_USER) \
		return CKR_USER_NOT_LOGGED_IN; \
	if(pMechanism == NULL) \
		return CKR_ARGUMENTS_BAD;

static CK_RV parseAesKeyTemplate(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, BYTE *pLabel, BYTE *pKcv, BYTE *bKeyLen, WORD *pwFlags)
{
	CK_ULONG i,v;

	for(i = 0; i < ulCount; i++)
	{
		if(pTemplate[i].pValue == NULL_PTR)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if(pTemplate[i].type == CKA_LABEL)
		{
			if(pTemplate[i].ulValueLen > 1 && pTemplate[i].ulValueLen <= TC_SECRET_KEY_LABEL_LEN )
				memcpy(pLabel,pTemplate[i].pValue,pTemplate[i].ulValueLen);
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else if(pTemplate[i].type == CKA_CHECK_VALUE)
		{
			if(pTemplate[i].ulValueLen == 3 )
				memcpy(pKcv,pTemplate[i].pValue,3);
			else
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else if (pTemplate[i].type == CKA_VALUE_LEN && pTemplate[i].ulValueLen == sizeof(CK_ULONG))
		{
			v = *((CK_ULONG_PTR)pTemplate[i].pValue);
			if(v != 16 && v != 24 && v != 32)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			*bKeyLen = v & 0xFF;
		}
		else if (pTemplate[i].type == CKA_ENCRYPT && pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
		{
			if(*((CK_BBOOL*)pTemplate[i].pValue))
				*pwFlags += TC_ATTR_ENCRYPT;
		}
		else if (pTemplate[i].type == CKA_DECRYPT && pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
		{
			if(*((CK_BBOOL*)pTemplate[i].pValue))
				*pwFlags += TC_ATTR_DECRYPT;
		}
		else if (pTemplate[i].type == CKA_WRAP && pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
		{
			if(*((CK_BBOOL*)pTemplate[i].pValue))
				*pwFlags += TC_ATTR_WRAP;
		}
		else if (pTemplate[i].type == CKA_UNWRAP && pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
		{
			if(*((CK_BBOOL*)pTemplate[i].pValue))
				*pwFlags += TC_ATTR_UNWRAP;
		}
		else if (pTemplate[i].type == CKA_EXTRACTABLE && pTemplate[i].ulValueLen == sizeof(CK_BBOOL))
		{
			if(*((CK_BBOOL*)pTemplate[i].pValue))
				*pwFlags += TC_ATTR_EXTRACT;
		}
		else
			return CKR_TEMPLATE_INCONSISTENT;
	}

	return CKR_OK;
}

/* C_GenerateKey generates a secret key, creating a new key
 * object. */
CK_RV C_GenerateKey
(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
	CK_VERSION sVersion;
	WORD wAesKeyFlags = 0;
	BYTE bAesKeyLen = 0;
	BYTE abAesLabel[TC_SECRET_KEY_LABEL_LEN+1];
	BYTE abCheckValue[3];
	CK_RV status;

	logFunc(__func__);

	COMMON_CHECKS();

	if(phKey == NULL)
		return CKR_ARGUMENTS_BAD;

	switch(pMechanism->mechanism)
	{
		case CKM_AES_KEY_GEN:
			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			// There has to be a template with at least three elements: CKA_LABEL, CKA_VALUE_LEN and one usage flag
			// Allowed usage flags are CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP and CKA_EXTRACTABLE
			if(ulCount < 3 || pTemplate == NULL_PTR)
				return CKR_TEMPLATE_INCONSISTENT;

			memset(abAesLabel,0,sizeof(abAesLabel));
			memset(abCheckValue,0,sizeof(abCheckValue));
			bAesKeyLen = 0;
			wAesKeyFlags = 0;

			// Get the info needed about the key
			status = parseAesKeyTemplate(pTemplate,ulCount, abAesLabel, abCheckValue, &bAesKeyLen,&wAesKeyFlags);
			if(status != CKR_OK)
				return status;

			// Check attributes are OK
			if(strlen((char*)abAesLabel) == 0 || bAesKeyLen == 0)
				return CKR_TEMPLATE_INCONSISTENT;

			// Now we have all the attributes, create the key
			if(!tcGenerateAesKey(abAesLabel,bAesKeyLen,wAesKeyFlags,phKey))
				return CKR_FUNCTION_FAILED;
			break;

		case CKM_SSL3_PRE_MASTER_KEY_GEN:

			// There is no need for a template as the attributes are added by the MULTOS app
			if(ulCount > 0)
				return CKR_ARGUMENTS_BAD;

			// Just one parameter, CK_VERSION
			if(pMechanism->ulParameterLen != sizeof(CK_VERSION))
				return CKR_MECHANISM_PARAM_INVALID;
			if(pMechanism->pParameter)
				sVersion = *((CK_VERSION_PTR)(pMechanism->pParameter));
			else
			{
				sVersion.major = 3;
				sVersion.minor = 3;
			}

			// Set up TLS as the current security environment
			//TODO: Redundant?
			if(!tcMseRestore(TC_ALGO_TLS))
				return CKR_FUNCTION_FAILED;

			if(!tcGeneratePreMasterSecret(sVersion.major,sVersion.minor,phKey))
				return CKR_FUNCTION_FAILED;
			break;

		default:
			return CKR_MECHANISM_INVALID;
			break;
	}
	return CKR_OK;
}


/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects. */
CK_RV C_GenerateKeyPair
(
  CK_SESSION_HANDLE    hSession,                    /* session
                                                     * handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen
                                                     * mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
                                                     * for pub.
                                                     * key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
                                                     * attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
                                                     * for priv.
                                                     * key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv.
                                                     * attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
                                                     * key
                                                     * handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
                                                     * priv. key
                                                     * handle */
)
{
	CK_ULONG i;
	CK_ULONG modulusBits = 0;
	CK_BYTE_PTR pPublicExponent = NULL;
	CK_BYTE_PTR pPublicKey = NULL;
	WORD EFPrivate = 0;
	WORD EFPublic = 0;
	WORD EFPrivateRequested = 0;
	CK_RV objCreateStatus = 0;
	CK_RV keyGenStatus = 0;
	CK_BYTE *pOID;
	CK_BYTE bNamedCurve = 0;
	CK_ULONG ulOIDLen;
	CK_ULONG ulPubKeyLen = 0;
	CK_ULONG ulPubKeySizeNeeded = 0;
	CK_BYTE abPubKey[140]; // Sized to hold biggest value it could be.

	logFunc(__func__);

	COMMON_CHECKS();

	switch(pMechanism->mechanism)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:

			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			// Extract the modulus bit length, buffer for the modulus and exponent (must be 65537) from the public key template. Error if not found or invalid
			if(ulPublicKeyAttributeCount < 2)
				return CKR_ARGUMENTS_BAD;
			for(i = 0; i < ulPublicKeyAttributeCount; i++)
			{
				if(pPublicKeyTemplate[i].type == CKA_MODULUS_BITS)
					modulusBits = *((CK_ULONG*)pPublicKeyTemplate[i].pValue);
				else if (pPublicKeyTemplate[i].type == CKA_PUBLIC_EXPONENT && pPublicKeyTemplate[i].ulValueLen == 3)
					pPublicExponent = (CK_BYTE_PTR)pPublicKeyTemplate[i].pValue;
				else if (pPublicKeyTemplate[i].type == CKA_MODULUS)
				{
					pPublicKey = (CK_BYTE_PTR)pPublicKeyTemplate[i].pValue;
					ulPubKeyLen = pPublicKeyTemplate[i].ulValueLen;
				}
				else if (pPublicKeyTemplate[i].type == CKA_ID)
					EFPrivateRequested = *((WORD*)pPublicKeyTemplate[i].pValue);
			}
			if(modulusBits == 0 || pPublicExponent == NULL || pPublicKey == NULL)
				return CKR_ARGUMENTS_BAD;

			// Check that the buffer in the template to store the modulus is big enough
			if(ulPubKeyLen < (modulusBits / 8))
				return CKR_ATTRIBUTE_VALUE_INVALID;

			// By default use the second key slot, the first being the primary device key
			if (EFPrivateRequested)
				EFPrivate = EFPrivateRequested;
			else
				EFPrivate = TC_EF_PRIVKEY_2;

			// Create the private key using the private key ID 61NN
			keyGenStatus = tcGenerateRsaKey(EFPrivate,modulusBits);
			if(keyGenStatus == 1)
				return CKR_ARGUMENTS_BAD;
			else if(keyGenStatus == 2)
				return CKR_FUNCTION_FAILED;

			// Get the public key modulus, filling in the relevant template attribute
			tcReadRsaModulus(EFPrivate,pPublicKey, (WORD)(modulusBits / 8));

			// Create the public key object using C_CreateObject passing in the public key template
			objCreateStatus = C_CreateObject(hSession,pPublicKeyTemplate,ulPublicKeyAttributeCount,(CK_OBJECT_HANDLE_PTR)&EFPublic);
			if (objCreateStatus != CKR_OK)
				return objCreateStatus;

			// Fill in the returned object handles
			*phPrivateKey = EFPrivate;
			*phPublicKey = EFPublic;
			break;

		case CKM_EC_KEY_PAIR_GEN:
			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			// Extract the private key file ID (if given), curve and location of the public key from the public key template
			if(ulPublicKeyAttributeCount < 3)
				return CKR_ARGUMENTS_BAD;
			for(i = 0; i < ulPublicKeyAttributeCount; i++)
			{
				if (pPublicKeyTemplate[i].type == CKA_EC_PARAMS)
				{
					pOID = (BYTE *)pPublicKeyTemplate[i].pValue;
					ulOIDLen = pPublicKeyTemplate[i].ulValueLen;
					if(ulOIDLen == sizeof(abDEROIDp256) && memcmp(abDEROIDp256,pOID,ulOIDLen) == 0)
					{
						ulPubKeySizeNeeded = 67; // 04 | 41 | 04 | Key (32x2)
						bNamedCurve = TC_NAMED_CURVE_P256;
					}
					else if(ulOIDLen == sizeof(abDEROIDp384) && memcmp(abDEROIDp384,pOID,ulOIDLen) == 0)
					{
						ulPubKeySizeNeeded = 99; // 04 | 61 | 04 | Key (48x2)
						bNamedCurve = TC_NAMED_CURVE_P384;
					}
					else if(ulOIDLen == sizeof(abDEROIDp521) && memcmp(abDEROIDp521,pOID,ulOIDLen) == 0)
					{
						ulPubKeySizeNeeded = 136; // 04 | 81 | 85 | 04 | Key (66x2)
						bNamedCurve = TC_NAMED_CURVE_P521;
					}
					else
						return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else if (pPublicKeyTemplate[i].type == CKA_EC_POINT)
				{
					pPublicKey = (CK_BYTE_PTR)pPublicKeyTemplate[i].pValue;
					ulPubKeyLen = pPublicKeyTemplate[i].ulValueLen;
				}
				else if (pPublicKeyTemplate[i].type == CKA_ID)
					EFPrivateRequested = *((WORD*)pPublicKeyTemplate[i].pValue);
			}
			if(bNamedCurve == 0 || ulPubKeySizeNeeded > ulPubKeyLen)
				return CKR_ARGUMENTS_BAD;

			// By default use the first key slot
			if (EFPrivateRequested)
				EFPrivate = EFPrivateRequested;
			else
				EFPrivate = TC_EFTYPE_EC_PRIVKEY;

			// Generate the key pair.
			if(g_loggedInUser == CKU_CONTEXT_SPECIFIC) // Key management user
			{
				// Key can be used for anything
				if(!tcGenerateEcKey(EFPrivate,bNamedCurve,0,abPubKey))
					return CKR_FUNCTION_FAILED;
			}
			else
			{
				// Key can only be used for ECDH1 key derivation
				if(!tcGenerateEcKey(EFPrivate,bNamedCurve,1,abPubKey))
					return CKR_FUNCTION_FAILED;
			}

			// Format it as needed for PKCS#11, the ECPoint structure, as a DER encoded ASN.1 OCTET_STRING
			pPublicKey[0] = 0x04; // ASN.1 OCTET_STRING
			if( bNamedCurve == TC_NAMED_CURVE_P521)
			{
				pPublicKey[1] = 0x81; // Indicates an additional length byte in DER
				pPublicKey[2] = 0x85; // The actual length (133)
				pPublicKey[3] = 0x04; // ECPoint type = Uncompressed
				memcpy(pPublicKey+4,abPubKey,132);
			}
			else
			{
				pPublicKey[1] = ulPubKeySizeNeeded - 2; // The length
				pPublicKey[2] = 0x04; // ECPoint type = Uncompressed
				memcpy(pPublicKey+3,abPubKey,ulPubKeySizeNeeded - 3);
			}

			// Create the public key object using C_CreateObject passing in the public key template
			objCreateStatus = C_CreateObject(hSession,pPublicKeyTemplate,ulPublicKeyAttributeCount,(CK_OBJECT_HANDLE_PTR)&EFPublic);
			if (objCreateStatus != CKR_OK)
				return objCreateStatus;

			// Fill in the returned object handles
			*phPrivateKey = EFPrivate;
			*phPublicKey = EFPublic;
			break;

		default:
			return CKR_MECHANISM_INVALID;
			break;
	}
	return CKR_OK;
}


/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_RV C_WrapKey
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
	WORD wFileSize = 0;

	logFunc(__func__);
	COMMON_CHECKS();

	if(pWrappedKey == NULL || pulWrappedKeyLen == NULL)
		return CKR_ARGUMENTS_BAD;

	switch(pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:
			if(!tcMseSetAlgo(TC_ALGO_RSA, TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			// If not the session object
			if(hWrappingKey != RSA_PUBLIC_KEY_SESSION_OBJECT)
			{
				// Load the token object
				if(!tcSelectEF(hWrappingKey,&wFileSize))
					return CKR_KEY_HANDLE_INVALID;

				if(!tcPreloadPublicKey(wFileSize))
					return CKR_FUNCTION_FAILED;
			}

			if(!tcWrapKey(hKey,pWrappedKey,pulWrappedKeyLen))
				return CKR_FUNCTION_FAILED;

			break;

		case CKM_AES_CBC:
			if(!tcMseSetKeyFile(hWrappingKey,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_KEY_HANDLE_INVALID;

			if(!tcMseSetAlgo(TC_ALGO_AES_CBC, TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			if(!tcWrapKey(hKey,pWrappedKey,pulWrappedKeyLen))
				return CKR_FUNCTION_FAILED;
			break;

		default:
			return CKR_MECHANISM_INVALID;
			break;
	}
	return CKR_OK;
}

/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_RV C_UnwrapKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	WORD wAesKeyFlags = 0;
	BYTE bAesKeyLen = 0;
	BYTE abAesLabel[TC_SECRET_KEY_LABEL_LEN+1];
	BYTE abCheckValue[3];
	CK_RV status;

	logFunc(__func__);
	COMMON_CHECKS();

	if(pWrappedKey == NULL || ulWrappedKeyLen == 0 || phKey == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	switch(pMechanism->mechanism)
	{
		case CKM_AES_CBC:
			// No mechanism info is required
			if(pMechanism->ulParameterLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			if(ulWrappedKeyLen != 16 && ulWrappedKeyLen != 32)
				return CKR_ARGUMENTS_BAD;

			// There has to be a template with at least four elements: CKA_LABEL, CKA_VALUE_LEN, CKA_CHECK_VALUE and one usage flag
			// Allowed usage flags are CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP and CKA_EXTRACTABLE
			if(ulAttributeCount < 4 || pTemplate == NULL_PTR)
				return CKR_TEMPLATE_INCONSISTENT;

			memset(abAesLabel,0,sizeof(abAesLabel));
			memset(abCheckValue,0,sizeof(abCheckValue));
			bAesKeyLen = 0;
			wAesKeyFlags = 0;

			if(!tcMseSetKeyFile(hUnwrappingKey,TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_KEY_HANDLE_INVALID;

			if(!tcMseSetAlgo(TC_ALGO_AES_CBC, TC_TEMPLATE_CONFIDENTIALITY))
				return CKR_FUNCTION_FAILED;

			// Build up the information about the key being imported from the attributes
			status = parseAesKeyTemplate(pTemplate,ulAttributeCount,abAesLabel,abCheckValue,&bAesKeyLen,&wAesKeyFlags);
			if(status != CKR_OK)
				return status;

			// Check attributes are OK
			if(strlen((char*)abAesLabel) == 0 || bAesKeyLen == 0 || (abCheckValue[0] == 0 && abCheckValue[1] == 0 && abCheckValue[2] == 0))
				return CKR_TEMPLATE_INCONSISTENT;

			// Can now do the unwrap
			if(!tcUnwrapKey(wAesKeyFlags,abAesLabel,abCheckValue,bAesKeyLen,pWrappedKey,ulWrappedKeyLen,phKey))
				return CKR_FUNCTION_FAILED;

			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}

/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_RV C_DeriveKey
(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR pMkdParams;
	CK_SSL3_KEY_MAT_PARAMS_PTR pKeyMatParams;
	CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParams;
	CK_BYTE *pOtherPublicKey;
	CK_ULONG ulOtherPublicKeyLen = 0;

	BYTE abSeed[64];

	logFunc(__func__);
	COMMON_CHECKS();

	switch(pMechanism->mechanism)
	{
		case CKM_TLS12_MASTER_KEY_DERIVE:

			if(phKey == NULL)
				return CKR_ARGUMENTS_BAD;

			// There is no need for a template as the attributes are added by the MULTOS app
			if(ulAttributeCount > 0)
				return CKR_ARGUMENTS_BAD;

			// Check parameter is correctly supplied
			if(pMechanism->ulParameterLen != sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS) || pMechanism->pParameter == NULL)
				return CKR_MECHANISM_PARAM_INVALID;
			pMkdParams = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR)(pMechanism->pParameter);
			if(pMkdParams->RandomInfo.ulClientRandomLen != 32 || pMkdParams->RandomInfo.ulServerRandomLen != 32)
				return CKR_MECHANISM_PARAM_INVALID;
			if(pMkdParams->pVersion == NULL || pMkdParams->RandomInfo.pClientRandom == NULL || pMkdParams->RandomInfo.pServerRandom == NULL)
				return CKR_MECHANISM_PARAM_INVALID;

			// Put the randoms in the correct order
			memcpy(abSeed,pMkdParams->RandomInfo.pClientRandom,32);
			memcpy(abSeed+32,pMkdParams->RandomInfo.pServerRandom,32);

			// Call MULTOS
			if(!tcGenerateMasterSecret(hBaseKey,FALSE,abSeed,64,phKey,&(pMkdParams->pVersion->major),&(pMkdParams->pVersion->minor)))
				return CKR_FUNCTION_FAILED;

			break;

		case CKM_TLS12_KEY_AND_MAC_DERIVE:
			// There is no need for a template as the attributes are added by the MULTOS app
			if(ulAttributeCount > 0)
				return CKR_ARGUMENTS_BAD;

			// Check parameter is correctly supplied
			if(pMechanism->ulParameterLen != sizeof(CK_SSL3_KEY_MAT_PARAMS) || pMechanism->pParameter == NULL)
				return CKR_MECHANISM_PARAM_INVALID;
			pKeyMatParams = (CK_SSL3_KEY_MAT_PARAMS_PTR)(pMechanism->pParameter);

			if(pKeyMatParams == NULL || pKeyMatParams->RandomInfo.pClientRandom == NULL || pKeyMatParams->RandomInfo.pServerRandom == NULL || pKeyMatParams->pReturnedKeyMaterial == NULL ||
					pKeyMatParams->pReturnedKeyMaterial->pIVClient == NULL || pKeyMatParams->pReturnedKeyMaterial->pIVServer == NULL)
				return CKR_MECHANISM_PARAM_INVALID;

			if(pKeyMatParams->RandomInfo.ulClientRandomLen != 32 || pKeyMatParams->RandomInfo.ulServerRandomLen != 32)
				return CKR_MECHANISM_PARAM_INVALID;

			// IV length can't be zero for this mechanism and the maximum we need is 128 (for AES)
			if(pKeyMatParams->ulIVSizeInBits == 0 || pKeyMatParams->ulIVSizeInBits > 128)
				return CKR_MECHANISM_PARAM_INVALID;

			// Only support AES keys of 128 or 256 bit lengths
			if(pKeyMatParams->ulKeySizeInBits != 128 && pKeyMatParams->ulKeySizeInBits != 256)
				return CKR_MECHANISM_PARAM_INVALID;

			// Only support MAC key based on SHA-256 (32 bytes * 8 bits) or no MAC key at all (not needed for GCM)
			if(!(pKeyMatParams->ulMacSizeInBits == 256 || pKeyMatParams->ulMacSizeInBits == 0))
				return CKR_MECHANISM_PARAM_INVALID;

			// Tell the MULTOS app about the key material needed.
			if(!tcMseSetTlsKeyLengths(pKeyMatParams->ulKeySizeInBits/8,pKeyMatParams->ulMacSizeInBits/8,pKeyMatParams->ulIVSizeInBits/8))
				return CKR_FUNCTION_FAILED;

			// Set the key in the security environment
			if(tcMseSetAlgo(TC_ALGO_TLS,TC_TEMPLATE_TLS) && tcMseSetKeyFile(hBaseKey,TC_TEMPLATE_TLS))
			{
				// Put the randoms in the required order
				memcpy(abSeed,pKeyMatParams->RandomInfo.pServerRandom,32);
				memcpy(abSeed+32,pKeyMatParams->RandomInfo.pClientRandom,32);

				if(!tcGenerateSessionKeys(abSeed,&(pKeyMatParams->pReturnedKeyMaterial->hClientMacSecret),
											&(pKeyMatParams->pReturnedKeyMaterial->hServerMacSecret),
											&(pKeyMatParams->pReturnedKeyMaterial->hClientKey),
											&(pKeyMatParams->pReturnedKeyMaterial->hServerKey),
											pKeyMatParams->pReturnedKeyMaterial->pIVClient,
											pKeyMatParams->pReturnedKeyMaterial->pIVServer))
					return CKR_FUNCTION_FAILED;
			}
			else
				return CKR_FUNCTION_FAILED;
			break;

		case CKM_ECDH1_DERIVE:
			if(phKey == NULL)
				return CKR_ARGUMENTS_BAD;

			// There is no need for a template as the attributes are added by the MULTOS app
			if(ulAttributeCount > 0)
				return CKR_ARGUMENTS_BAD;

			// Check parameter is correctly supplied
			if(pMechanism->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS) || pMechanism->pParameter == NULL)
				return CKR_MECHANISM_PARAM_INVALID;

			pEcdhParams = (CK_ECDH1_DERIVE_PARAMS_PTR)(pMechanism->pParameter);

			// Check contents of the parameters
			// No KDF is used, so no shared data either
			if(pEcdhParams->kdf != CKD_NULL || pEcdhParams->pSharedData != NULL || pEcdhParams->ulSharedDataLen != 0)
				return CKR_MECHANISM_PARAM_INVALID;

			// Can only accept raw public keys or those formatted as per CKA_EC_POINT.
			if(pEcdhParams->ulPublicDataLen == 67 || pEcdhParams->ulPublicDataLen == 99 || pEcdhParams->ulPublicDataLen == 135 )
			{
				// CKA_EC_POINT format.
				if(pEcdhParams->pPublicData[0] != 0x04)	// ASN.1 OCTET_STRING
					return CKR_MECHANISM_PARAM_INVALID;
				if(pEcdhParams->pPublicData[1] == 0x81)
				{
					if(pEcdhParams->pPublicData[3] != 0x04)	// ECPoint format = uncompressed
						return CKR_MECHANISM_PARAM_INVALID;
					ulOtherPublicKeyLen = pEcdhParams->pPublicData[2] - 1;
				}
				else
				{
					if(pEcdhParams->pPublicData[2] != 0x04)	// ECPoint format = uncompressed
						return CKR_MECHANISM_PARAM_INVALID;
					ulOtherPublicKeyLen = pEcdhParams->pPublicData[1] - 1;
				}
				// The actual point is at the end of the data.
				pOtherPublicKey = pEcdhParams->pPublicData + pEcdhParams->ulPublicDataLen - ulOtherPublicKeyLen;
			}
			else if(pEcdhParams->ulPublicDataLen == 64 || pEcdhParams->ulPublicDataLen == 96 || pEcdhParams->ulPublicDataLen == 128 )
			{
				// The raw data
				ulOtherPublicKeyLen = pEcdhParams->ulPublicDataLen;
				pOtherPublicKey = pEcdhParams->pPublicData;
			}
			else
				// Not formatted correctly
				return CKR_MECHANISM_PARAM_INVALID;

			// Set up the algorithm and private key to use in the TLS template
			if(!tcMseSetAlgo(TC_ALGO_ECDH1,TC_TEMPLATE_TLS) || !tcMseSetKeyFile(hBaseKey,TC_TEMPLATE_TLS))
				return CKR_FUNCTION_FAILED;

			// Finally do it
			if(!tcGeneratePreMasterSecretAlgo(pOtherPublicKey,ulOtherPublicKeyLen,phKey))
				return CKR_FUNCTION_FAILED;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}
