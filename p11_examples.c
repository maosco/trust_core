/*
* Example PKCS#11 calls. The functions shown do not include any parameter validation.
*/
#include <stdlib.h>	// For malloc
#include <string.h> // For memcpy
#include <stdio.h>
#include <time.h>
#include <pkcs11.h>

#define DEVICE_KEY_LEN	256	// 2048 bit
#define SHA256_DIGEST_LEN		32	// SHA-256
#define AES_BLOCK_LEN 16
#define TLS_RANDOM_LEN 32
#define MAX_ADDN_DATA_LEN	256
#define EPHEMERAL_KEY_HANDLE 0x6303
#define TC_NAMED_CURVE_P256		0x17
#define TC_NAMED_CURVE_P384		0x18
#define TC_NAMED_CURVE_P521		0x19

// ASN.1 template for RSA-SHA256 signature
static unsigned char abSha256SigTemplate[] = {
0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20, // ASN.1 sequence for sha-256
0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc // The actual hash goes here
};

// DER encoded ASN.1 Object IDs for different NIST curves
unsigned char abDEROIDp256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
unsigned char abDEROIDp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
unsigned char abDEROIDp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
	
// TLS variables
static CK_OBJECT_HANDLE hPMS, hMS, hCWK, hSWK, hCMK, hSMK;
#define CIPHERSUITE_MAX_BLOCK_LEN	64
static unsigned char abClientIv[CIPHERSUITE_MAX_BLOCK_LEN];
static unsigned char abServerIv[CIPHERSUITE_MAX_BLOCK_LEN];
unsigned char abClientRandom[TLS_RANDOM_LEN];
unsigned char abServerRandom[TLS_RANDOM_LEN];
static CK_BYTE bCipherSuiteMacLen = SHA256_DIGEST_LEN; // AES-CBC. For AES-GCM = 0
static CK_BYTE bCipherSuiteBlockLen = AES_BLOCK_LEN;
static CK_BYTE abAdditionalData[MAX_ADDN_DATA_LEN];
static CK_ULONG ulAdditionalDataLen = 0;

static CK_SESSION_HANDLE hSession = 0;	// Set when calling C_OpenSession

CK_ULONG sha256(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pOut)
{
	CK_MECHANISM mechanism;
	CK_ULONG ulLen = 32;	// pOut must point to a buffer at least this big

	mechanism.mechanism = CKM_SHA256;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;
	C_DigestInit(hSession,&mechanism);
	C_Digest(hSession,pData,ulDataLen,pOut,&ulLen);
	return(ulLen);
}

CK_ULONG hmac256(CK_BYTE_PTR pIn, CK_ULONG ulInLen,  unsigned char client, CK_BYTE_PTR pOut,  CK_ULONG ulOutSize)
{
	CK_ULONG ulLen;
	CK_OBJECT_HANDLE hKey;
	CK_MECHANISM mechanism;
	CK_RV status;

	if(client)
		hKey = hCMK;
	else
		hKey = hSMK;

	mechanism.mechanism = CKM_SHA256_HMAC;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	status = C_SignInit(hSession,&mechanism,hKey);

	ulLen = ulOutSize;
	status = C_Sign(hSession,pIn,ulInLen,pOut,&ulLen);
	if(status == CKR_OK)
		return ulLen;
	else
		return 0;
}

CK_ULONG aesGcmEncipher(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pIV)
{
	CK_ULONG ulLen;
	CK_MECHANISM mechanism;
	CK_GCM_PARAMS gcmParams;
	CK_RV status;
	CK_ULONG ulTagLen = 16;


	gcmParams.pAAD = abAdditionalData;
	gcmParams.ulAADLen = ulAdditionalDataLen;
	gcmParams.ulTagBits = ulTagLen*8;
	gcmParams.ulIvLen = 12;
	gcmParams.pIv = pIv;
	mechanism.mechanism = CKM_AES_GCM;
	mechanism.pParameter = (CK_VOID_PTR)&gcmParams;
	mechanism.ulParameterLen = sizeof(gcmParams);
	status = C_EncryptInit(hSession,&mechanism,hCWK);
	if( status != CKR_OK )
		return(0);

	ulLen = ulDataLen + ulTagLen;
	status = C_Encrypt(hSession,pData, ulDataLen,pData,&ulLen);
	if( status == CKR_OK )
		return ulLen;

	return(0);
}


CK_ULONG finalFinishMAC(char *sLabel, CK_BYTE_PTR pHandShakeHash, CK_ULONG ulHashLen, CK_BYTE_PTR pOut,  CK_ULONG ulOutSize)
{
	CK_ULONG ulLen;
	CK_TLS_MAC_PARAMS macParams;
	CK_MECHANISM mechanism;
	CK_MECHANISM_TYPE sha256Mech = CKM_SHA256;

	if(strcmp(sLabel,"server finished") == 0)
		macParams.ulServerOrClient = 1; // Server
	else if (strcmp(sLabel,"client finished") == 0)
		macParams.ulServerOrClient = 2; // Client
	else
		return 0;

	macParams.prfHashMechanism = sha256Mech;
	macParams.ulMacLength = 12;
	mechanism.mechanism = CKM_TLS12_MAC;
	mechanism.pParameter = (CK_VOID_PTR)&macParams;
	mechanism.ulParameterLen = sizeof(macParams);
	C_SignInit(hSession,&mechanism,hMS);

	ulLen = ulOutSize;
	if (C_Sign(hSession,pHandShakeHash,ulHashLen,pOut,&ulLen) == CKR_OK)
		return ulLen;

	return 0;
}


// Returns the length of the encrypted pre-master secret (RSA), 1 (ECDH success) or 0 (failure)
CK_ULONG preMasterSecret(CK_BYTE bMajor, CK_BYTE bMinor, CK_BYTE_PTR pPubKey, CK_ULONG ulPubKeyKen, CK_BYTE_PTR pExponent, CK_BYTE bExpLen, CK_BYTE_PTR pOut,  CK_ULONG ulOutSize, CK_BYTE bEcdheMode)
{
	CK_ULONG len = 0;
	CK_MECHANISM mechanism;
	CK_ECDH1_DERIVE_PARAMS ecdhParams;
	CK_BYTE abECPoint[160];
	CK_ULONG ulPointLen = 0;
	CK_RV status;

	// Template for an untrusted RSA public key object
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL itsFalse = 0;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_OBJECT_HANDLE hUntrustedKey;
	CK_VERSION ver = {bMajor,bMinor};
	CK_ATTRIBUTE pubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyType,sizeof(keyType)},
			{CKA_MODULUS,(CK_VOID_PTR)pPubKey,ulPubKeyKen},
			{CKA_PUBLIC_EXPONENT,(CK_VOID_PTR)pExponent, bExpLen}
	};

	if(bEcdheMode)
	{
		// First format the input public key as an DER encoded ECPoint
		abECPoint[0] = 0x04;
		if(ulPubKeyKen == 132)
		{
			abECPoint[1] = 0x81;
			abECPoint[2] = ulPubKeyKen+1;
			abECPoint[3] = 0x04;
			memcpy(abECPoint+4,pPubKey,ulPubKeyKen);
			ulPointLen = ulPubKeyKen + 4;
		}
		else
		{
			abECPoint[1] = ulPubKeyKen+1;
			abECPoint[2] = 0x04;
			memcpy(abECPoint+3,pPubKey,ulPubKeyKen);
			ulPointLen = ulPubKeyKen + 3;
		}

		ecdhParams.kdf = CKD_NULL;
		ecdhParams.pSharedData = NULL;
		ecdhParams.ulSharedDataLen = 0;
		ecdhParams.pPublicData = abECPoint;
		ecdhParams.ulPublicDataLen = ulPointLen;
		mechanism.mechanism = CKM_ECDH1_DERIVE;
		mechanism.pParameter = (CK_VOID_PTR)&ecdhParams;
		mechanism.ulParameterLen = sizeof(ecdhParams);
		status = C_DeriveKey(hSession,&mechanism,EPHEMERAL_KEY_HANDLE,NULL,0,&hPMS);
		if( status == CKR_OK)
			len = 1;
	}
	else
	{
		// Generate PMS
		mechanism.mechanism = CKM_SSL3_PRE_MASTER_KEY_GEN;
		mechanism.pParameter = (CK_VOID_PTR)&ver;
		mechanism.ulParameterLen = sizeof(ver);
		C_GenerateKey(hSession,&mechanism,NULL,0,&hPMS);

		// Import RSA key to use for wrapping
		C_CreateObject(hSession,pubKeyTemplate,5,&hUntrustedKey);

		// Wrap PMS
		mechanism.mechanism = CKM_RSA_PKCS;
		mechanism.pParameter = NULL;
		mechanism.ulParameterLen = 0;
		len = ulOutSize;
		C_WrapKey(hSession,&mechanism,hUntrustedKey,hPMS,pOut,&len);
	}
	return len;
}

CK_BBOOL masterSecret(CK_BYTE_PTR pServerRandom)
{
	CK_VERSION versionOut;
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS mkdParams;
	CK_MECHANISM mechanism;

	// Save the server random for later use
	memcpy(abServerRandom,pServerRandom,TLS_RANDOM_LEN);

	mkdParams.pVersion = &versionOut;
	mkdParams.RandomInfo.pClientRandom = abClientRandom;
	mkdParams.RandomInfo.pServerRandom = abServerRandom;
	mkdParams.RandomInfo.ulClientRandomLen = TLS_RANDOM_LEN;
	mkdParams.RandomInfo.ulServerRandomLen = TLS_RANDOM_LEN;
	mechanism.mechanism = CKM_TLS12_MASTER_KEY_DERIVE;
	mechanism.pParameter = (CK_VOID_PTR)&mkdParams;
	mechanism.ulParameterLen = sizeof(mkdParams);
	return (C_DeriveKey(hSession,&mechanism,hPMS,NULL,0,&hMS) == CKR_OK);
}


CK_BBOOL tlsSessionKeys(CK_BYTE_PTR *pClientIvPtr, CK_BYTE_PTR *pServerIvPtr)
{
	CK_SSL3_KEY_MAT_PARAMS keyMatParams;
	CK_SSL3_KEY_MAT_OUT	   keyMat;
	CK_MECHANISM mechanism;
	CK_RV status;

	keyMatParams.RandomInfo.pClientRandom = abClientRandom;
	keyMatParams.RandomInfo.pServerRandom = abServerRandom;
	keyMatParams.RandomInfo.ulClientRandomLen = TLS_RANDOM_LEN;
	keyMatParams.RandomInfo.ulServerRandomLen = TLS_RANDOM_LEN;
	keyMatParams.ulKeySizeInBits = bCipherSuiteKeyLen * 8;
	keyMatParams.ulMacSizeInBits = bCipherSuiteMacLen * 8;
	keyMatParams.ulIVSizeInBits = bCipherSuiteIvLen * 8;
	keyMatParams.pReturnedKeyMaterial = &keyMat;
	keyMat.pIVClient = abClientIv;
	keyMat.pIVServer = abServerIv;
	mechanism.mechanism = CKM_TLS12_KEY_AND_MAC_DERIVE;
	mechanism.pParameter = (CK_VOID_PTR)&keyMatParams;
	mechanism.ulParameterLen = sizeof(keyMatParams);
	status = C_DeriveKey(hSession,&mechanism,hMS,NULL,0,NULL);
	hCMK = keyMat.hClientMacSecret;
	hSMK = keyMat.hServerMacSecret;
	hCWK = keyMat.hClientKey;
	hSWK = keyMat.hServerKey;
	*pClientIvPtr = abClientIv;
	*pServerIvPtr = abServerIv;

	return(status == CKR_OK);
}

// Verify a X.509 signature that is RSA / SHA256 based
CK_BBOOL rsaVerify(CK_BYTE_PTR pModulus, CK_ULONG ulModLen, CK_BYTE_PTR pExponent, CK_BYTE bExpLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature)
{
	CK_MECHANISM mechanism;
	CK_RV status;

	// Template for an untrusted public key object
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL itsFalse = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_OBJECT_HANDLE hUntrustedKey;
	CK_ATTRIBUTE pubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyType,sizeof(keyType)},
			{CKA_MODULUS,(CK_VOID_PTR)pModulus,ulModLen},
			{CKA_PUBLIC_EXPONENT,(CK_VOID_PTR)pExponent, bExpLen}
	};

	// Upload the public key to the app as an untrusted session key
	if (C_CreateObject(hSession,pubKeyTemplate,5,&hUntrustedKey) != CKR_OK )
		return CK_FALSE;

	// Hash the data provided and place the output into the signature template
	// This forms the plain text to compare the signature too
	sha256(pData,ulDataLen,abSha256SigTemplate+sizeof(abSha256SigTemplate)-SHA256_DIGEST_LEN);

	mechanism.mechanism = CKM_RSA_PKCS;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	status = C_VerifyInit(hSession,&mechanism,hUntrustedKey);
	if(status != CKR_OK)
		return CK_FALSE;
	
	status = C_Verify(hSession,abSha256SigTemplate,sizeof(abSha256SigTemplate),pSignature,ulModLen);
	if(status != CKR_OK)
		return CK_FALSE;
	
	return (CK_TRUE);
}

// Assumes 2048 bit MULTOS device key
CK_ULONG rsaSignPKCS1_type1(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR *pOutPtr, CK_OBJECT_HANDLE hRsaPrivKey)
{
	CK_BYTE_PTR p;
	CK_ULONG len = 0;
	CK_ULONG wSigLen;
	CK_MECHANISM mechanism;

	// Create working buffer the size of the RSA public key. Caller to free pointer when finished with it
	p = (CK_BYTE_PTR)malloc(DEVICE_KEY_LEN);
	if(p == NULL)
		return 0;

	// Copy in the signature template
	memcpy(p,abSha256SigTemplate,sizeof(abSha256SigTemplate));

	// SHA256 the data directly into the template
	sha256(pData,ulDataLen,p+sizeof(abSha256SigTemplate)-SHA256_DIGEST_LEN);

	mechanism.mechanism = CKM_RSA_PKCS;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	C_SignInit(hSession,&mechanism,hRsaPrivKey);
	wSigLen = DEVICE_KEY_LEN;
	if ( C_Sign(hSession,(CK_BYTE*)p,DEVICE_KEY_LEN,p,&wSigLen) == CKR_OK )
		len = wSigLen;
	*pOutPtr = p;

	return len;
}

CK_ULONG rsaSignPKCS1_PSS(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR *pOutPtr, CK_OBJECT_HANDLE hRsaPrivKey)
{
	CK_ULONG wSigLen;
	CK_BYTE_PTR p;
	CK_ULONG len;
	CK_MECHANISM mechanism;

	// Create working buffer the size of the RSA public key. Caller to free pointer when finished with it
	p = (CK_BYTE_PTR)malloc(DEVICE_KEY_LEN);
		return 0;

	// Hash the data (using MULTOS)
	sha256(pData,ulDataLen,p);

	// Call MULTOS to sign
	mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	C_SignInit(hSession,&mechanism,hRsaPrivKey);
	wSigLen = DEVICE_KEY_LEN;
	if ( C_Sign(hSession,(CK_BYTE*)p,DEVICE_KEY_LEN,p,&wSigLen) == CKR_OK )
		len = wSigLen;
	*pOutPtr = p;
	return len;
}

CK_ULONG ecdsaSign(CK_BYTE_PTR pHash, CK_ULONG ulHashLen, CK_BYTE_PTR pSignature, CK_OBJECT_HANDLE hPubKey)
{
	CK_MECHANISM mechanism;
	CK_ULONG ulLen;
	CK_ULONG ulSigLen = 0;

	mechanism.mechanism = CKM_ECDSA;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	if( C_SignInit(hSession,&mechanism,hPubKey) == CKR_OK)
	{
		ulLen = 132; // Assumes pSignature is big enough for the largest signature possible
		if(C_Sign(hSession,pHash,ulHashLen,pSignature,&ulLen) == CKR_OK)
			ulSigLen = ulLen;
	}
	return ulSigLen;
}

CK_BBOOL ecdsaVerify(CK_BYTE_PTR pPubKey, CK_ULONG ulPubKeyKen, CK_BYTE bNamedCurve, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature)
{
	CK_MECHANISM mechanism;
	int n = 0;
	CK_OBJECT_HANDLE hUntrustedKey;
	CK_BYTE abHash[64];
	CK_ULONG ulLen;
	CK_RV status;

	// PKCS#11 template for creating the session object to hold the public key to verify with
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL itsFalse = CK_FALSE;
	CK_BYTE bEcPrimeLen;
	unsigned char pubKey[66*2+4]; // To hold the ASN.1 OCTET_STRING version of the public key
	CK_KEY_TYPE keyTypeEcc = CKK_EC;
	unsigned short wNotUsed = 0;
	CK_ATTRIBUTE ecPubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyTypeEcc,sizeof(keyTypeEcc)},
			{CKA_ID,(CK_VOID_PTR)&wNotUsed,sizeof(wNotUsed)},
			{CKA_EC_POINT,(CK_VOID_PTR)pubKey,sizeof(pubKey)},
			{CKA_EC_PARAMS,(CK_VOID_PTR)abDEROIDp256,sizeof(abDEROIDp256)}
		};

	if(bNamedCurve == TC_NAMED_CURVE_P256)
		bEcPrimeLen = 32;
	else if(bNamedCurve == TC_NAMED_CURVE_P384)
		bEcPrimeLen = 48;
	else if(bNamedCurve == TC_NAMED_CURVE_P521)
		bEcPrimeLen = 64;

	// Set up the ECPoint entry
	n = 0;
	pubKey[n++] = 0x04;
	if(bEcPrimeLen == 66)
		pubKey[n++] = 0x81;
	pubKey[n++] = (2*bEcPrimeLen)+1;
	pubKey[n++] = 0x04;
	memcpy(pubKey+n,pPubKey,ulPubKeyKen);
	n += ulPubKeyKen;
	ecPubKeyTemplate[4].ulValueLen = n;

	// Set the curve to use in the template - default is P256
	mechanism.mechanism = CKM_SHA256;
	if(bNamedCurve == TC_NAMED_CURVE_P384)
	{
		ecPubKeyTemplate[5].pValue = abDEROIDp384;
		ecPubKeyTemplate[5].ulValueLen = sizeof(abDEROIDp384);
		mechanism.mechanism = CKM_SHA384;
	}
	else if (bNamedCurve == TC_NAMED_CURVE_P521)
	{
		ecPubKeyTemplate[5].pValue = abDEROIDp521;
		ecPubKeyTemplate[5].ulValueLen = sizeof(abDEROIDp521);
		mechanism.mechanism = CKM_SHA512;
	}

	if (C_CreateObject(hSession,ecPubKeyTemplate,6,&hUntrustedKey) != CKR_OK )
		return CK_FALSE;

	// Hash the input data
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;
	C_DigestInit(hSession,&mechanism);
	ulLen = sizeof(abHash);
	if(mechanism.mechanism == CKM_SHA512)
	{
		abHash[0] = 0;
		abHash[1] = 0;
		ulLen -= 2;
		status = C_Digest(hSession,pData,ulDataLen,abHash+2,&ulLen);
	}
	else
		status = C_Digest(hSession,pData,ulDataLen,abHash,&ulLen);

	if(status != CKR_OK)
		return CK_FALSE;

	// Do the verification
	mechanism.mechanism = CKM_ECDSA;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	status = C_VerifyInit(hSession,&mechanism,hUntrustedKey);
	if(status != CKR_OK)
		return CK_FALSE;
	
	status = C_Verify(hSession,abHash,ulLen,pSignature,ulPubKeyKen);
	if(status != CKR_OK)
		return CK_FALSE;
	
	return (CK_TRUE);
}

int generateEphemeralECKey(CK_BYTE bNamedCurve,CK_BYTE_PTR pPubKey)
{
	CK_MECHANISM mechanism;

	// Template for generating "ephemeral" EC key
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL itsFalse = CK_FALSE;
	CK_BYTE bEcPrimeLen = 32; // Default to P-256
	unsigned char pubKey[66*2+4]; // To hold the ASN.1 OCTET_STRING version of the public key
	CK_KEY_TYPE keyTypeEcc = CKK_EC;
	unsigned short ecEphemeralKeyHandle = EPHEMERAL_KEY_HANDLE;
	CK_OBJECT_HANDLE hEcPriv,hEcPub;
	CK_ATTRIBUTE ecPubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyTypeEcc,sizeof(keyTypeEcc)},
			{CKA_ID,(CK_VOID_PTR)&ecEphemeralKeyHandle,sizeof(ecEphemeralKeyHandle)},
			{CKA_EC_POINT,(CK_VOID_PTR)pubKey,sizeof(pubKey)},	// an output
			{CKA_EC_PARAMS,(CK_VOID_PTR)abDEROIDp256,sizeof(abDEROIDp256)}
		};

	if(bNamedCurve == TC_NAMED_CURVE_P256)
		bEcPrimeLen = 32;
	else if(bNamedCurve == TC_NAMED_CURVE_P384)
		bEcPrimeLen = 48;
	else if(bNamedCurve == TC_NAMED_CURVE_P521)
		bEcPrimeLen = 64;
	ecPubKeyTemplate[4].ulValueLen = (2*bEcPrimeLen)+3;

	// Set the curve to use in the template - default is P256
	if(bNamedCurve == TC_NAMED_CURVE_P384)
	{
		ecPubKeyTemplate[5].pValue = abDEROIDp384;
		ecPubKeyTemplate[5].ulValueLen = sizeof(abDEROIDp384);
	}
	else if (bNamedCurve == TC_NAMED_CURVE_P521)
	{
		ecPubKeyTemplate[5].pValue = abDEROIDp521;
		ecPubKeyTemplate[5].ulValueLen = sizeof(abDEROIDp521);

		// The DER length is > 0x7F so there is an extra length byte.
		ecPubKeyTemplate[4].ulValueLen ++;
	}

	mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;
	if( C_GenerateKeyPair(hSession,&mechanism,ecPubKeyTemplate,6,NULL_PTR,0,&hEcPub,&hEcPriv) == CKR_OK)
	{
		// Extract the raw public key
		if(bEcPrimeLen == 66)
			memcpy(pPubKey,ecPubKeyTemplate[4].pValue+4,bEcPrimeLen*2);
		else
			memcpy(pPubKey,ecPubKeyTemplate[4].pValue+3,bEcPrimeLen*2);

		return CK_TRUE;
	}
	return CK_FALSE;
}

