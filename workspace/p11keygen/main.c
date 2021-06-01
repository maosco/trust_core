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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <multosio.h>
#include <pkcs11.h>
#ifdef _WIN32
#include<conio.h>
#else
#include <ncurses.h>
#endif
#include <ctype.h>
#include "asn1.h"

extern void base64Encode(unsigned char *pData, unsigned short wInputLen, unsigned short *pwOutputLen, char *pEncodedData);

#define RSA_MOD_LEN 256
#define EC_PRIME_MAX_LEN 66

// ASN.1 values
static unsigned char abDEROIDp256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static unsigned char abDEROIDp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static unsigned char abDEROIDp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

typedef struct
{
	unsigned char fixed1[33];
	unsigned char modulus[RSA_MOD_LEN];
	unsigned char fixed2;
	unsigned char expLen;
	unsigned char exponent[3];
} pkcsPubKey256_t;

static pkcsPubKey256_t pubKeySeq = {
	{ 0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00},
	{ 0xbe,0x79,0xca,0x73,0x0a,0x73,0x0c,0xee,0x19,0xc1,0x19,0x1f,0x0d,0xcb,0xc7,0x03,0x9d,0xf3,0xbc,0xd1,0x37,0x9c,0x1e,0xaa,0x1a,0x63,0xe7,0xd9,0x09,0x0e,0x87,0x91,0x7d,0xbc,0x87,0xd8,0xb0,0x15,0x08,0x6b,0xeb,0x89,0x42,0x26,0xab,0xd1,0x0a,0x10,0x88,0x31,0x54,0x1c,0x1c,0xc2,0xc0,0x32,0xa0,0x80,0xdb,0x21,0x99,0x98,0xd8,0x72,0xaa,0xe3,0x49,0x9b,0x3b,0x05,0x49,0x58,0xea,0xff,0x35,0x1e,0x4d,0x41,0x2e,0x39,0x8f,0x3e,0xf2,0x07,0xa0,0xf3,0xdb,0x42,0x2d,0x37,0x76,0x6c,0xe7,0x76,0x19,0x7a,0x4e,0x8c,0xa8,0x39,0x58,0xbc,0xdc,0x12,0x70,0x92,0x72,0x65,0xd8,0x18,0xe9,0x29,0x13,0xed,0x7a,0xb9,0x2a,0x72,0x44,0x55,0xc3,0xc2,0x09,0x53,0x8b,0xbd,0x37,0xe5,0xa9,0x3b,0x02,0xbd,0x5f,0x59,0xf7,0x1b,0x63,0xc0,0x14,0x61,0x03,0xb8,0xe9,0x3c,0x0a,0xa7,0x4b,0xf1,0x3c,0xe3,0x4c,0xe5,0xc7,0xf4,0xa6,0x29,0x3d,0xb3,0x0e,0x09,0x4f,0xb3,0x91,0x96,0x40,0x95,0x78,0x79,0xe3,0x4f,0x88,0x7f,0xb3,0x55,0x4a,0xe9,0x74,0x40,0x23,0xb1,0x8a,0xfc,0x06,0x42,0xbf,0x39,0xee,0x09,0xcb,0x79,0xee,0x7d,0x1b,0x7a,0x43,0x96,0xd1,0xdb,0x4a,0x32,0x7c,0x54,0xad,0x37,0xfa,0xe3,0x7b,0x6a,0xd4,0x6f,0xe8,0x6d,0x62,0x95,0xf1,0x4f,0xb9,0x69,0x6d,0x61,0x64,0xa8,0x97,0x10,0xb4,0xe5,0x69,0x98,0x69,0x88,0x34,0x81,0xf4,0x97,0x12,0xc8,0x94,0x4c,0xe7,0x17,0x55,0x40,0x14,0x37,0x34,0x0b,0xc2,0x7a,0xf7,0x2d,0x60,0x6c,0xfc,0xf6,0x45,0x5d },
	0x02,
	0x03,
	{ 0x01, 0x00, 0x01 }
};

typedef struct
{
	unsigned char keyTypeAndCurve[23];
	unsigned char asnHeader[4];
	unsigned char pubKey[0x40];
}pkcsEcPubKey256_t;

typedef struct
{
	unsigned char keyTypeAndCurve[20];
	unsigned char asnHeader[4];
	unsigned char pubKey[0x60];
}pkcsEcPubKey384_t;

typedef struct
{
	unsigned char keyTypeAndCurve[21];
	unsigned char asnHeader[5];
	unsigned char pubKey[0x84];
}pkcsEcPubKey521_t;

static pkcsEcPubKey256_t ecPubKeySeq256 = {
		{0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07},
		{0x03,0x42,0x00,0x04},
		{0xfd,0xf1,0x28,0x73,0x30,0xb9,0x6c,0xf1,0xc7,0xfa,0x2e,0x48,0x60,0xc2,0xdb,0x79,0x18,0x95,0xcb,0xe6,0xcd,0x7e,0xbb,0x0a,0xbd,0xb9,0x64,0xeb,0xf2,0xfb,0xa8,0xe2,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92}
};

static pkcsEcPubKey384_t ecPubKeySeq384 = {
		{0x30,0x76,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,0x22},
		{0x03,0x62,0x00,0x04},
		{0xfd,0xf1,0x28,0x73,0x30,0xb9,0x6c,0xf1,0xc7,0xfa,0x2e,0x48,0x60,0xc2,0xdb,0x79,0x18,0x95,0xcb,0xe6,0xcd,0x7e,0xbb,0x0a,0xbd,0xb9,0x64,0xeb,0xf2,0xfb,0xa8,0xe2,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92}
};

static pkcsEcPubKey521_t ecPubKeySeq521 = {
		{0x30,0x81,0x9B,0x30,0x10,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x05,0x2B,0x81,0x04,0x00,0x23},
		{0x03,0x81,0x86,0x00,0x04},
		{0x00,0x00,0x00,0x00,
		 0xfd,0xf1,0x28,0x73,0x30,0xb9,0x6c,0xf1,0xc7,0xfa,0x2e,0x48,0x60,0xc2,0xdb,0x79,0x18,0x95,0xcb,0xe6,0xcd,0x7e,0xbb,0x0a,0xbd,0xb9,0x64,0xeb,0xf2,0xfb,0xa8,0xe2,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92,
		 0x83,0x9e,0xcb,0x36,0x34,0xef,0x83,0x8e,0xd9,0xcc,0x35,0x63,0xc7,0x5e,0x8c,0xc9,0xbc,0x56,0x89,0xbc,0xe7,0x58,0x27,0x15,0x29,0x8e,0x46,0x30,0x54,0x51,0x82,0x92}
};

static unsigned char PIN[] = {0x31, 0x32, 0x33, 0x34, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static unsigned char abSha256SigTemplate[] = {
0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20, // ASN.1 sequence for sha-256
0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc // The actual hash goes here
};



char *pkcsErrorText(CK_RV code)
{
	switch(code)
	{
		case CKR_ARGUMENTS_BAD: return "Arguments bad";
		case CKR_CANT_LOCK: return "Can't lock";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "Crypto already initialised";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "Cryptoki not intialised";
		case CKR_DEVICE_ERROR: return "Device error";
		case CKR_DEVICE_REMOVED: return "Device removed";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "Encrypted data length range";
		case CKR_FUNCTION_FAILED: return "MULTOS function returned a failure code";
		case CKR_FUNCTION_NOT_SUPPORTED: return "Function not supported";
		case CKR_KEY_HANDLE_INVALID: return "Key handle invalid";
		case CKR_MECHANISM_INVALID: return "Mechanism invalid";
		case CKR_MECHANISM_PARAM_INVALID: return "Mechanism parameter invalid";
		case CKR_OPERATION_NOT_INITIALIZED: return "Operation not initialised";
		case CKR_OK: return "OK";
		case CKR_PIN_INCORRECT: return "PIN incorrect";
		case CKR_PIN_LOCKED: return "PIN locked";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "Random seed not supported";
		case CKR_SESSION_COUNT: return "Session count (max exceeded)";
		case CKR_SESSION_HANDLE_INVALID: return "Session handle invalid";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "Session parallel not supported";
		case CKR_SESSION_READ_ONLY_EXISTS: return "Read-only session exists (cannot log in to read-only session)";
		case CKR_SIGNATURE_INVALID: return "Signature invalid";
		case CKR_SIGNATURE_LEN_RANGE: return "Signature length range";
		case CKR_SLOT_ID_INVALID: return "Slot ID invalid";
		case CKR_TOKEN_NOT_PRESENT: return "Token not present";
		case CKR_USER_ALREADY_LOGGED_IN: return "User already logged in";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "Another user already logged in";
		case CKR_USER_TYPE_INVALID: return "User type not valid";
		case CKR_USER_NOT_LOGGED_IN: return "User not logged in";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "Attribute value invalid";
		default: return "Unknown error";
	}
}

#ifdef _WIN32
int enterSecret(CK_BYTE_PTR pData, CK_ULONG wLen, char *sPrompt)
{
	int i;
	CK_BYTE b;

    printf("%s\n",sPrompt);

    for(i=0; i<wLen;i++)
	{
        b = _getch();
        printf("*");

		// Stop if enter key pressed
        if(b == '\r')
            break;
		else
			pData[i] = b;

		// If backspace pressed
        if(pData[i] == '\b')
		{
            if(i == 0)                
				printf("\b \b");	
            else if (i >= 1)
			{
                pData[i-1] = '\0';
                i = i - 2;                
				printf("\b \b\b \b");
            }
         }
    }
	printf("\n");
	return i;
}
#else
int enterSecret(CK_BYTE_PTR pData, CK_ULONG wLen, char *sPrompt)
{
	int i;
	unsigned char ch;

	initscr();
	printw(sPrompt);
	printw("\n");
	noecho();
	i = 0;
	do
	{
		ch = getch();
		if(ch != 10) // Return
		{
			printw("*");
			pData[i] = ch;
			i++;
		}
	}
	while(ch != 10 && i < wLen);
	echo();
	printw("\n");
	endwin();
	return i;
}
#endif

int enterPIN(CK_BYTE_PTR pPIN, CK_ULONG wLen, char *sPrompt)
{
	memset(pPIN,0xFF,wLen);
	return enterSecret(pPIN,wLen,sPrompt);
}



static void deleteExistingPublicKey(CK_SESSION_HANDLE hSession, char *label)
{
	CK_ULONG ulObjectsFound;
	CK_ULONG publicKey = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE searchPublic[] = {{CKA_CLASS,&publicKey,sizeof(CK_ULONG)},{CKA_LABEL,label,strlen(label)}};
	CK_OBJECT_HANDLE foundObjects[10];
	CK_ULONG i;

	ulObjectsFound = 0;
	if( C_FindObjectsInit(hSession,searchPublic,2) == CKR_OK)
	{
		if (C_FindObjects(hSession,foundObjects,10,&ulObjectsFound) == CKR_OK)
		{
			for(i = 0; i < ulObjectsFound; i++)
			{
				printf("Destroying existing public key %s (%04x)\n",label,(unsigned) foundObjects[i]);
				C_DestroyObject(hSession,foundObjects[i]);
			}
		}
	}
	C_FindObjectsFinal(hSession);
}

/*
static void dumpHex(unsigned char *pData, unsigned short wLen)
{
	unsigned short i;

	for(i=0;i<wLen;i++)
		printf("%02x",pData[i]);
	printf("\n");
}
*/

// As well as creating the required key pair, this function can optionally generate a self-signed
// CSR in PEM format
static int generateKeyPair(CK_SESSION_HANDLE hSession, unsigned char bECC, unsigned char bEcPrimeLen, unsigned short wKeyId, int genCsr, char *sFileName, char *sCountryName, char *sStateOrProvinceName, char *sLocalityName, char *sOrgName, char *sOrgUnit, char *sCommonName, char *sEmailAddress)
{
	// Stuff for building the ASN.1 sequences and signing data
	unsigned short wPubKeySeqLen = 0;
	unsigned char abInfoSeq[7*128 + 4];
	unsigned short wInfoSeqLen = 0;
	unsigned char abSigData[1024];
	unsigned short wSigDataLen = 0;
	unsigned char abSignature[RSA_MOD_LEN*2];
	unsigned short wSigLen = 0;
	unsigned char abHash[66]; // Biggest size is for SHA-512 + 2 extra bytes needed for P-521 key length
	unsigned long ulHashLen;
	unsigned char abFullSeq[1024];
	unsigned short wSeqLen = 0;
	char sCertRequest[2048];
	unsigned short wCertReqLen = 0;

	// PKCS#11 call parameters
	CK_RV status;
	CK_MECHANISM keyGenMechanism,shaMechanism,signingMechanism;
	CK_ULONG dwModlenInBits = RSA_MOD_LEN * 8;
	CK_BYTE abExponent[] = {1,0,1}; //65537
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_BBOOL itsTrue = 1;
	CK_BBOOL itsFalse = 0;
	CK_KEY_TYPE keyTypeRsa = CKK_RSA;
	CK_KEY_TYPE keyTypeEcc = CKK_EC;
	unsigned short privateKeyHandle = 0x6100 + wKeyId;
	unsigned short ecPrivateKeyHandle = 0x6300 + wKeyId;
	char label[] = "KEY0";
	char ecLabel[] = "ECKEY0";

	// The public key template is dictated by the object type in the PKCS#11 interface
	CK_ATTRIBUTE rsaPubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyTypeRsa,sizeof(keyTypeRsa)},
			{CKA_ID,(CK_VOID_PTR)&privateKeyHandle,2}, // Use this to pass a specific handle for the private key
			{CKA_SUBJECT,NULL_PTR,0},
			{CKA_ENCRYPT,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_VERIFY,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_VERIFY_RECOVER,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_WRAP,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_MODULUS,(CK_VOID_PTR)pubKeySeq.modulus,sizeof(pubKeySeq.modulus)},	// here this is an output
			{CKA_MODULUS_BITS,(CK_VOID_PTR)&dwModlenInBits,sizeof(dwModlenInBits)},
			{CKA_PUBLIC_EXPONENT,(CK_VOID_PTR)&abExponent, sizeof(abExponent)},
			{CKA_LABEL,(CK_VOID_PTR)label,sizeof(label)-1}
	};

	unsigned char pubKey[EC_PRIME_MAX_LEN*2+4]; // To hold the ASN.1 OCTET_STRING version of the public key
	CK_BYTE_PTR pEcPubKeySeq = NULL;
	CK_ATTRIBUTE ecPubKeyTemplate[] = {
			{CKA_CLASS,(CK_VOID_PTR)&pubKeyClass,sizeof(pubKeyClass)},
			{CKA_TOKEN,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_KEY_TYPE,(CK_VOID_PTR)&keyTypeEcc,sizeof(keyTypeEcc)},
			{CKA_ID,(CK_VOID_PTR)&ecPrivateKeyHandle,2}, // Use this to pass a specific handle for the private key
			{CKA_SUBJECT,NULL_PTR,0},
			{CKA_ENCRYPT,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_VERIFY,(CK_VOID_PTR)&itsTrue,sizeof(itsTrue)},
			{CKA_VERIFY_RECOVER,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_WRAP,(CK_VOID_PTR)&itsFalse,sizeof(itsFalse)},
			{CKA_EC_POINT,(CK_VOID_PTR)pubKey,sizeof(pubKey)},	// an output
			{CKA_EC_PARAMS,(CK_VOID_PTR)abDEROIDp256,sizeof(abDEROIDp256)},
			{CKA_LABEL,(CK_VOID_PTR)ecLabel,sizeof(ecLabel)-1}
	};
	CK_OBJECT_HANDLE hPrivKey = 0;
	CK_OBJECT_HANDLE hPubKey = 0;

	FILE *fp;

	printf("Generating key pair...\n");
	if(bECC)
	{
		// Update the key label to reflect the key id and delete any public key that exists for that label
		ecLabel[5] = 0x30 + (wKeyId & 0xFF);
		deleteExistingPublicKey(hSession, ecLabel);

		// CKA_EC_POINT size varies
		ecPubKeyTemplate[9].ulValueLen = (2*bEcPrimeLen)+3;

		// Set the curve to use - default is P256
		if(bEcPrimeLen == 48)
		{
			ecPubKeyTemplate[10].pValue = abDEROIDp384;
			ecPubKeyTemplate[10].ulValueLen = sizeof(abDEROIDp384);
		}
		else if (bEcPrimeLen == 66)
		{
			ecPubKeyTemplate[10].pValue = abDEROIDp521;
			ecPubKeyTemplate[10].ulValueLen = sizeof(abDEROIDp521);

			// The DER length is > 0x7F so there is an extra length byte.
			ecPubKeyTemplate[9].ulValueLen ++;
		}

		// The public key gets put into the CKA_EC_POINT attribute of the public key template
		keyGenMechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
		keyGenMechanism.pParameter = NULL;
		keyGenMechanism.ulParameterLen = 0;
		status = C_GenerateKeyPair(hSession,&keyGenMechanism,ecPubKeyTemplate,12,NULL_PTR,0,&hPubKey,&hPrivKey);

		// Copy the raw public key (i.e. removing the ASN.1 OCTET_STRING header) into the public key sequence
		if(bEcPrimeLen == 32)
		{
			memcpy(ecPubKeySeq256.pubKey,pubKey+3,sizeof(ecPubKeySeq256.pubKey));
			wPubKeySeqLen = sizeof(ecPubKeySeq256);
			pEcPubKeySeq = (CK_BYTE_PTR)&ecPubKeySeq256;

			shaMechanism.mechanism = CKM_SHA256;
		}
		else if(bEcPrimeLen == 48)
		{
			memcpy(ecPubKeySeq384.pubKey,pubKey+3,sizeof(ecPubKeySeq384.pubKey));
			wPubKeySeqLen = sizeof(ecPubKeySeq384);
			pEcPubKeySeq = (CK_BYTE_PTR)&ecPubKeySeq384;

			shaMechanism.mechanism = CKM_SHA384;
		}
		else
		{
			memcpy(ecPubKeySeq521.pubKey,pubKey+4,sizeof(ecPubKeySeq521.pubKey));
			wPubKeySeqLen = sizeof(ecPubKeySeq521);
			pEcPubKeySeq = (CK_BYTE_PTR)&ecPubKeySeq521;

			shaMechanism.mechanism = CKM_SHA512;
		}
	}
	else
	{
		// Update the key label to reflect the key id and delete any public key that exists for that label
		label[3] = 0x30 + (wKeyId & 0xFF);
		deleteExistingPublicKey(hSession, label);

		// The modulus gets put into the CKA_MODULUS attribute of the public template
		keyGenMechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
		keyGenMechanism.pParameter = NULL;
		keyGenMechanism.ulParameterLen = 0;
		status = C_GenerateKeyPair(hSession,&keyGenMechanism,rsaPubKeyTemplate,13,NULL_PTR,0,&hPubKey,&hPrivKey);
		wPubKeySeqLen = sizeof(pubKeySeq);

		// Set up the hashing mechanism
		shaMechanism.mechanism = CKM_SHA256;
	}
	if( status != CKR_OK)
	{
		printf("ERROR: Key pair generation failed (%s)\n",pkcsErrorText(status));
		return 0;
	}
	printf("Private key object=%04x, public key=%04x\n",(unsigned int)hPrivKey,(unsigned int)hPubKey);


	if(genCsr)
	{
		printf("Self signing CSR request data...\n");

		// Generate the Certificate Information sequence from the input parameters
		wInfoSeqLen = makeCertInfoSequence(abInfoSeq,sizeof(abInfoSeq),sCountryName,sStateOrProvinceName,sLocalityName,sOrgName,sOrgUnit,sCommonName,sEmailAddress);

		// Combine the info and key sequences into the sequence to be signed
		if(bECC)
			wSigDataLen = makeSigDataSequence(abSigData,sizeof(abSigData),abInfoSeq,wInfoSeqLen,pEcPubKeySeq,wPubKeySeqLen);
		else
			wSigDataLen = makeSigDataSequence(abSigData,sizeof(abSigData),abInfoSeq,wInfoSeqLen,(unsigned char*)&pubKeySeq,wPubKeySeqLen);

		// Hash the data to be signed, the hash mechanism should already be set to the desired one.
		shaMechanism.pParameter = NULL;
		shaMechanism.ulParameterLen = 0;
		status = C_DigestInit(hSession,&shaMechanism);
		if(status != CKR_OK)
		{
			printf("ERROR: Signature data hashing init failed (%s)\n",pkcsErrorText(status));
			return(0);
		}
		memset(abHash,0,sizeof(abHash));
		if(shaMechanism.mechanism == CKM_SHA512)
		{
			status = C_Digest(hSession,abSigData,wSigDataLen,abHash+2,&ulHashLen);
			ulHashLen += 2;
		}
		else
			status = C_Digest(hSession,abSigData,wSigDataLen,abHash,&ulHashLen);
		if(status != CKR_OK)
		{
			printf("ERROR: Signature data hashing failed: (%s)\n",pkcsErrorText(status));
			return(0);
		}

		//printf("Hash = ");
		//dumpHex(abHash,ulHashLen);

		// Sign the request sequence using MULTOS
		if(bECC)
		{
			// Sign using ECDSA
			signingMechanism.mechanism = CKM_ECDSA;
			signingMechanism.pParameter = NULL;
			signingMechanism.ulParameterLen = 0;
			status = C_SignInit(hSession,&signingMechanism,hPrivKey);
			if (status != CKR_OK)
			{
				printf("ERROR: Cert Request self signing Init failed (%s)\n",pkcsErrorText(status));
				return 0;
			}
			wSigLen = sizeof(abSignature);
			status = C_Sign(hSession,abHash,ulHashLen,abSignature,(CK_ULONG_PTR)&wSigLen);
			if (status != CKR_OK)
			{
				printf("ERROR: Cert Request self signing Sign failed (%s)\n",pkcsErrorText(status));
				return 0;
			}

			// Note: signing method sequences are all the same number of bytes long
			wSeqLen = wSigDataLen + getEcSignMethodLength() + 9 + wSigLen;

			// Extend length if R and/or S parts of the signature need left padding with 0x00 to ensure they remain as positive INTs.
			if(abSignature[0] > 0x7F)
				wSeqLen++;
			if(abSignature[bEcPrimeLen] > 0x7F)
				wSeqLen++;
			// Extend length if 521 bit as the signature is longer
			if(bEcPrimeLen == 66)
				wSeqLen += 2;

			if(wSeqLen + 4 > sizeof(abFullSeq))
			{
				fprintf(stderr,"ERROR: CSR sequence too long\n");
				return 0;
			}
		}
		else
		{
			// Copy SHA-256 hash into template
			memcpy(abSha256SigTemplate+19,abHash,ulHashLen);

			// Sign using RSA PKCS#1
			signingMechanism.mechanism = CKM_RSA_PKCS;
			signingMechanism.pParameter = NULL;
			signingMechanism.ulParameterLen = 0;
			status = C_SignInit(hSession,&signingMechanism,hPrivKey);
			if (status != CKR_OK)
			{
				printf("ERROR: Cert Request self signing Init failed (%s)\n",pkcsErrorText(status));
				return 0;
			}
			wSigLen = sizeof(abSignature);
			status = C_Sign(hSession,abSha256SigTemplate,sizeof(abSha256SigTemplate),abSignature,(CK_ULONG_PTR)&wSigLen);
			if (status != CKR_OK)
			{
				printf("ERROR: Cert Request self signing Sign failed (%s)\n",pkcsErrorText(status));
				return 0;
			}

			wSeqLen = wSigDataLen + getRsaSignMethodLength() + 5 + RSA_MOD_LEN;
			if(wSeqLen + 4 > sizeof(abFullSeq))
			{
				fprintf(stderr,"ERROR: CSR sequence too long\n");
				return 0;
			}
		}

		//printf("Signature (%u) = ",wSigLen);
		//dumpHex(abSignature,wSigLen);

		// Construct full CSR sequence
		printf("Completing CSR...\n");

		if(bECC)
			wSeqLen = makeEccCsrSequence(abFullSeq,sizeof(abFullSeq),wSeqLen,abSigData,wSigDataLen,abSignature,bEcPrimeLen);
		else
			wSeqLen = makeRsaCsrSequence(abFullSeq,sizeof(abFullSeq),wSeqLen,abSigData,wSigDataLen,abSignature,wSigLen);

		// Convert to Base64
		memset(sCertRequest,0,sizeof(sCertRequest));
		base64Encode(abFullSeq,wSeqLen,&wCertReqLen,sCertRequest);

		// Output to PEM file with necessary header and trailer
		fp = fopen(sFileName,"w");
		if(!fp)
		{
			fprintf(stderr,"ERROR: Failed to open PEM file %s\n",sFileName);
			return 0;
		}
		fprintf(fp,"-----BEGIN CERTIFICATE REQUEST-----\n");
		fprintf(fp,"%s",sCertRequest);
		fprintf(fp,"\n-----END CERTIFICATE REQUEST-----\n");
		fclose(fp);
	}
	return 1; //OK
}

// ------------------------------------------------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
	CK_SESSION_HANDLE session;
	CK_RV status;
	unsigned short wKeyId;
	int genStatus = 0;
	int pinLen = 4; // Default is 1234
	CK_BYTE bECC = 0;
	CK_BYTE bECPrimeLen = 0;

	if(argc != 11 && argc != 3 && argc != 2 )
	{
		printf("usage: p11keygen <keyType> <keyId>|-v [<csr filename> <country name> <state or province name> <locality name> <org name> <org unit> <common name> <email address>]\n");
		printf("  Generate an key pair with or without a self-signed CSR\n\n");
		printf("  CSR arguments should be quoted if they contain spaces\n");
		printf("  keyType       'R' (RSA) or \"Ennn\" (ECC with key size nnn)\n");
		printf("  keyId         0-3\n");
		printf("  -v            Print version\n");
		return 0;
	}

	if(strcmp(argv[1],"-v") == 0)
	{
		printf("Version: 0.1\n");
		return 0;
	}

	if(argv[1][0] != 'R' && argv[1][0] != 'E')
	{
		fprintf(stdout,"keyType must be R or E\n");
		return 1;
	}
	bECC = argv[1][0] == 'R' ? 0 : 1;
	if(bECC)
	{
		if(strcmp(argv[1],"E256") == 0)
			bECPrimeLen = 32;
		else if(strcmp(argv[1],"E384") == 0)
			bECPrimeLen = 48;
		else if(strcmp(argv[1],"E521") == 0)
			bECPrimeLen = 66;
		else
		{
			fprintf(stdout,"Invalid ECC key size. Valid values are 256, 384 or 521\n");
			return 1;
		}
	}

	wKeyId = (unsigned short)atoi(argv[2]);
	if(!bECC && wKeyId > 1)
	{
		fprintf(stdout,"RSA keyId argument must be 0 or 1\n");
		return 1;
	}
	if(bECC && wKeyId > 3)
	{
		fprintf(stdout,"ECC keyId argument must be 0,1,2 or 3\n");
		return 1;
	}

	// Initialise
	printf("Initialising HSM...\n");
	status = C_Initialize(NULL);
	if(status != CKR_OK)
	{
		printf("ERROR: Init failed (%s)\n",pkcsErrorText(status));
		return 1;
	}
	status = C_OpenSession(1,CKF_SERIAL_SESSION | CKF_RW_SESSION,NULL_PTR,NULL_PTR,&session);
	if(status != CKR_OK)
	{
		C_Finalize(NULL);
		printf("ERROR: Open Session failed (%s)\n",pkcsErrorText(status));
		return 1;
	}
	// Verify PIN-K pin
	pinLen = enterPIN(PIN,sizeof(PIN),"Enter PIN-K");
	status = C_Login(session,CKU_CONTEXT_SPECIFIC,PIN,pinLen);
	if(status != CKR_OK)
	{
		C_Finalize(NULL);
		printf("ERROR: Login failed (%s)\n",pkcsErrorText(status));
		return 1;
	}

	if(argc == 3)
		genStatus = generateKeyPair(session, bECC, bECPrimeLen, wKeyId, 0, "", "", "", "", "", "", "", "" );
	else
		genStatus = generateKeyPair(session, bECC, bECPrimeLen, wKeyId, 1, argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], argv[9], argv[10]);
	if(genStatus)
	{
		C_CloseSession(session);
		C_Finalize(NULL);
		printf("OK\n");
		return 0;
	}
	else
	{
		C_CloseSession(session);
		C_Finalize(NULL);
		printf("FAILED\n");
		return 1;
	}
}
