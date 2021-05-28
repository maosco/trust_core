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

#include <multosio.h>
#include <stdlib.h>	// For malloc
#include <string.h> // For memcpy
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include "tc_api.h"

// ASN.1 values
#define ASN1_SEQ 0x30
#define ASN1_SET 0x31
#define ASN1_INT 0x02
#define ASN1_OID 0x06
#define ASN1_PrintableString 0x13
#define ASN1_UTF8String 0x0C
#define ASN1_IA5String 0x16
#define ASN1_NULL 0x05
#define ASN1_ZERO 0xA0
#define ASN1_BitString 0x03

static unsigned char OID_CN[] = {0x55, 0x04, 0x06};
static unsigned char OID_ST[] = {0x55, 0x04, 0x08};
static unsigned char OID_LO[] = {0x55, 0x04, 0x07};
static unsigned char OID_OR[] = {0x55, 0x04, 0x0A};
static unsigned char OID_OU[] = {0x55, 0x04, 0x0B};
static unsigned char OID_CM[] = {0x55, 0x04, 0x03};
static unsigned char OID_EM[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01};

static unsigned char ASN1_SEQ_SIGN_METHOD[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00};

extern void base64Encode(unsigned char *data, unsigned short input_length,unsigned short *output_length,char *encoded_data);

#define MAX_DATA_PAYLOAD 2992
#define MAX_DIGEST_INPUT_BLOCK 2992
#define MAX_LABEL_LEN	22
#define MAX_ADDN_DATA_LEN	256
#define DEVICE_KEY_LEN	256	// 2048 bit
#define SHA256_DIGEST_LEN		32	// SHA-256
#define SHA1_DIGEST_LEN	20
#define INTERNAL_HASH	1
#define HANDSHAKE_HASH	0
#define FIRST_BLOCK	 0
#define CONTINUATION_BLOCK 1
#define TLS_RANDOM_LEN 32
#define GCM_IV_LEN 12		// 4 bytes fixed + 8 byte counter
#define GCM_TAG_LEN 16
#define EPHEMERAL_KEY_HANDLE TC_EFTYPE_EC_PRIVKEY+3
#define TLS_RSA_WITH_AES_128_CBC_SHA    0x002F
#define TLS_RSA_WITH_AES_256_CBC_SHA    0x0035
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x003C
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003D
#define TLS_RSA_WITH_AES_128_GCM_SHA256		  0x009C
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xC023
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xC027
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xC02F

static unsigned char abSha256SigTemplate[] = {
0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20, // ASN.1 sequence for sha-256
0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc // The actual hash goes here
};

// ASN.1 encoded public key
typedef struct
{
	BYTE fixed1[33];
	BYTE modulus[DEVICE_KEY_LEN];
	BYTE fixed2;
	BYTE expLen;
	BYTE exponent[3];
} pkcsPubKey256_t;

pkcsPubKey256_t devicePubKey = {
	{ 0x30,0x82,0x01,0x22,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0f,0x00,0x30,0x82,0x01,0x0a,0x02,0x82,0x01,0x01,0x00},
	{ 0xbe,0x79,0xca,0x73,0x0a,0x73,0x0c,0xee,0x19,0xc1,0x19,0x1f,0x0d,0xcb,0xc7,0x03,0x9d,0xf3,0xbc,0xd1,0x37,0x9c,0x1e,0xaa,0x1a,0x63,0xe7,0xd9,0x09,0x0e,0x87,0x91,0x7d,0xbc,0x87,0xd8,0xb0,0x15,0x08,0x6b,0xeb,0x89,0x42,0x26,0xab,0xd1,0x0a,0x10,0x88,0x31,0x54,0x1c,0x1c,0xc2,0xc0,0x32,0xa0,0x80,0xdb,0x21,0x99,0x98,0xd8,0x72,0xaa,0xe3,0x49,0x9b,0x3b,0x05,0x49,0x58,0xea,0xff,0x35,0x1e,0x4d,0x41,0x2e,0x39,0x8f,0x3e,0xf2,0x07,0xa0,0xf3,0xdb,0x42,0x2d,0x37,0x76,0x6c,0xe7,0x76,0x19,0x7a,0x4e,0x8c,0xa8,0x39,0x58,0xbc,0xdc,0x12,0x70,0x92,0x72,0x65,0xd8,0x18,0xe9,0x29,0x13,0xed,0x7a,0xb9,0x2a,0x72,0x44,0x55,0xc3,0xc2,0x09,0x53,0x8b,0xbd,0x37,0xe5,0xa9,0x3b,0x02,0xbd,0x5f,0x59,0xf7,0x1b,0x63,0xc0,0x14,0x61,0x03,0xb8,0xe9,0x3c,0x0a,0xa7,0x4b,0xf1,0x3c,0xe3,0x4c,0xe5,0xc7,0xf4,0xa6,0x29,0x3d,0xb3,0x0e,0x09,0x4f,0xb3,0x91,0x96,0x40,0x95,0x78,0x79,0xe3,0x4f,0x88,0x7f,0xb3,0x55,0x4a,0xe9,0x74,0x40,0x23,0xb1,0x8a,0xfc,0x06,0x42,0xbf,0x39,0xee,0x09,0xcb,0x79,0xee,0x7d,0x1b,0x7a,0x43,0x96,0xd1,0xdb,0x4a,0x32,0x7c,0x54,0xad,0x37,0xfa,0xe3,0x7b,0x6a,0xd4,0x6f,0xe8,0x6d,0x62,0x95,0xf1,0x4f,0xb9,0x69,0x6d,0x61,0x64,0xa8,0x97,0x10,0xb4,0xe5,0x69,0x98,0x69,0x88,0x34,0x81,0xf4,0x97,0x12,0xc8,0x94,0x4c,0xe7,0x17,0x55,0x40,0x14,0x37,0x34,0x0b,0xc2,0x7a,0xf7,0x2d,0x60,0x6c,0xfc,0xf6,0x45,0x5d },
	0x02,
	0x03,
	{ 0x01, 0x00, 0x01 }
};

// TLS variables
static CK_OBJECT_HANDLE hPMS, hMS, hCWK, hSWK, hCMK, hSMK;
#define CIPHERSUITE_MAX_BLOCK_LEN	64
static unsigned char abClientIv[CIPHERSUITE_MAX_BLOCK_LEN];
static unsigned char abServerIv[CIPHERSUITE_MAX_BLOCK_LEN];
unsigned char abClientRandom[TLS_RANDOM_LEN]; // Needs to be accessible outside of the module
unsigned char abServerRandom[TLS_RANDOM_LEN]; // Needs to be accessible outside of the module
static unsigned char bCipherSuiteMacLen = SHA256_DIGEST_LEN;
static unsigned char bCipherSuiteBlockLen = AES_BLOCK_LEN;
static unsigned char bCipherAlgo = TC_ALGO_AES_CBC;
static unsigned char bCipherSuiteIvLen = AES_BLOCK_LEN;
static unsigned char bEcdheMode = 0;
static unsigned char abAdditionalData[MAX_ADDN_DATA_LEN];
static unsigned short wAdditionalDataLen = 0;

// To trap overlapping hashing
static unsigned char bShaInProgress = 0;

static void outputMsg(FILE *channel, char *format, ...)
{
	va_list args;
	va_start(args, format);

	fprintf(channel, format, args);

	va_end(args);
}

// Makes the assumption that SET elements will be < 128 bytes long
static unsigned char asn1MakeSet(unsigned char *pOid, unsigned char bOidLen, unsigned char bType, char *pValue, unsigned char *pOut)
{
	int valueLen = strlen(pValue);
	int l = 6 + bOidLen + valueLen;
	int i;

	if (l >= 128)
		return 0;

	i = 0;
	pOut[i++] = ASN1_SET;
	pOut[i++] = l;
	pOut[i++] = ASN1_SEQ;
	pOut[i++] = l-2;
	pOut[i++] = ASN1_OID;
	pOut[i++] = bOidLen;
	memcpy(pOut+i,pOid,bOidLen);
	i += bOidLen;
	pOut[i++] = bType;
	pOut[i++] = valueLen;
	memcpy(pOut+i,pValue,valueLen);
	i += valueLen;

	// Return the length of the set
	return (i);
}

static unsigned short mtlsSha256Init(void)
{	
	if(bShaInProgress)
	{
		outputMsg(stderr,"ERROR: mtlsSha256Init() - SHA already in progress\n");
		return 0;
	}
	if(tcShaInit(SHA256_DIGEST_LEN))
	{
		bShaInProgress = 1;
		return 1;
	}
	else
		return 0;
}

static unsigned short mtlsSha256Update(unsigned char *pData, unsigned short wLen)
{
	unsigned short wNumBlocks = wLen / MAX_DIGEST_INPUT_BLOCK;
	unsigned short wRemain = wLen % MAX_DIGEST_INPUT_BLOCK;
	unsigned short i;

	// Full blocks first
	for(i = 0; i < wNumBlocks; i++)
	{
		if(!tcShaUpdate(pData+(i*MAX_DIGEST_INPUT_BLOCK),MAX_DIGEST_INPUT_BLOCK))
			return 0;
	}
	// Then the final block
	return tcShaUpdate(pData+(i*MAX_DIGEST_INPUT_BLOCK),wRemain);
}

static unsigned short mtlsSha256Final(unsigned char *pOut)
{
	bShaInProgress = 0;
	return tcShaFinal(pOut);
}

void mtlsVersion(unsigned char *major, unsigned char *minor)
{
	*major = 1;
	*minor = 1;
}

int mtlsFinish(void)
{
	tcEraseTLSKeys();
	multosDeselectCurrApplication();
	return (1);
}

int mtlsHandshakeHashInit(void)
{
	//printf("mtlsHandshakeHashInit\n");
	return tcHandshakeShaInit(SHA256_DIGEST_LEN);
}

int mtlsHandshakeHashUpdate(unsigned char *pData, unsigned short wLen)
{
	unsigned short wNumBlocks = wLen / MAX_DIGEST_INPUT_BLOCK;
	unsigned short wRemain = wLen % MAX_DIGEST_INPUT_BLOCK;
	unsigned short i;

	//printf("mtlsHandshakeHashUpdate: Adding %u bytes to handshake hash\n",wLen);
	// Full blocks first
	for(i = 0; i < wNumBlocks; i++)
	{
		if(!tcHandshakeShaUpdate(pData+(i*MAX_DIGEST_INPUT_BLOCK),MAX_DIGEST_INPUT_BLOCK))
			return 0;
	}
	// Then the final block
	return tcHandshakeShaUpdate(pData+(i*MAX_DIGEST_INPUT_BLOCK),wRemain);
}

unsigned short mtlsHandshakeHashCurrent(unsigned char *pOut)
{
	//printf("mtlsHandshakeHashCurrent\n");
	return tcHandshakeShaFinal(pOut);
}

int mtlsInit(unsigned short wCipherSuite)
{
	char acPinData[TC_PIN_SIZE];
	FILE *fp;
	//char hex[128];
	BYTE abRand[8];
	int i;

	// Initialise the HAL first
	if(!multosInit())
	{
		outputMsg(stderr,"ERROR: mtlsInit(): Failed to initialise HAL\n");
		return 0;
	}

	// See if the app is already selected by calling a harmless function
	if(!tcAskRandom(sizeof(abRand),abRand))
	{
		multosReset(); // Will force app to be deselected if really reset

		// Select the MULTOS app
		if(!tcSelectApp())
		{
			outputMsg(stderr,"ERROR: mtlsInit(): Failed to select MULTOS application\n");
			return 0;
		}
	}

	// Set the cipher suite if specified
	if(wCipherSuite)
	{
		if(!tcMseSetCipherSuite(wCipherSuite))
		{
			outputMsg(stderr,"ERROR: mtlsInit(): Failed to set cipher suite\n");
			return 0;
		}

		// Set cipher suite encryption / decryption block length - ONLY SUPPORT AES at the moment
		bCipherSuiteBlockLen = AES_BLOCK_LEN;

		// Set cipher suite hash length
		if(wCipherSuite == TLS_RSA_WITH_AES_128_CBC_SHA || wCipherSuite == TLS_RSA_WITH_AES_256_CBC_SHA)
			bCipherSuiteMacLen = SHA1_DIGEST_LEN;
		else
			bCipherSuiteMacLen = SHA256_DIGEST_LEN;

		// Set parameters for the encryption algorithm
		bCipherAlgo = TC_ALGO_AES_CBC;
		bCipherSuiteIvLen = AES_BLOCK_LEN;
		if(wCipherSuite == TLS_RSA_WITH_AES_128_GCM_SHA256 || wCipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || wCipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		{
			bCipherAlgo = TC_ALGO_AES_GCM;
			bCipherSuiteIvLen = GCM_IV_LEN;
			bCipherSuiteMacLen = 0; // GCM doesn't use HMAC
		}

		// Set the mode for generating pre-master secrets
		bEcdheMode = 0;
		if(wCipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || wCipherSuite == TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ||
			wCipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 || wCipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
			bEcdheMode = 1;
	}

	// Load the PIN from the file
	memset(acPinData,0xFF,sizeof(acPinData));
	fp = fopen("user_pin.txt","r");
	if(fp == NULL)
	{
		outputMsg(stderr,"WARNING: mtlsInit(): Failed to open user_pin.txt. Using 1234\n");
		acPinData[0] = '1';
		acPinData[1] = '2';
		acPinData[2] = '3';
		acPinData[3] = '4';
	}
	else
	{
		fgets(acPinData,sizeof(acPinData),fp);
		fclose(fp);

		// Remove NULL and possible newline characters 0x0D and 0x0A
		for(i = strlen(acPinData); i >= 0 && (acPinData[i] == 0x0A || acPinData[i] == 0x0D || acPinData[i] == 0x00); i--)
			acPinData[i] = 0xFF;
	}
	// Validate the PIN
	//multosBinToHex((BYTE*)acPinData,hex,TC_PIN_SIZE);
	//printf("%s\n",hex);
	if(!tcVerifyPIN2(TC_PINREF_G,(CK_BYTE*)acPinData))
	{
		outputMsg(stderr,"ERROR: mtlsInit(): PIN verification failed\n");
		return 0;
	}
	return 1;
}

unsigned short mtlsHMAC(unsigned char *pIn, unsigned short wInLen,  unsigned char client, unsigned char *pOut,  unsigned short wOutSize)
{
	unsigned short wLen;

	// Cannot use HMAC with ciphersuites that don't have MAC keys
	if(bCipherSuiteMacLen == 0)
	{
		outputMsg(stderr,"ERROR: mtlsHMAC(): cannot be called with current ciphersuite\n");
		return 0;
	}

	// Set up security environment
	if(client)
		tcMseSetKeyFile(hCMK,TC_TEMPLATE_DIGITAL_SIG);
	else
		tcMseSetKeyFile(hSMK,TC_TEMPLATE_DIGITAL_SIG);

	if(bCipherSuiteMacLen == SHA256_DIGEST_LEN)
		tcMseSetAlgo(TC_ALGO_SHA256_HMAC,TC_TEMPLATE_DIGITAL_SIG);
	else
		tcMseSetAlgo(TC_ALGO_SHA1_HMAC,TC_TEMPLATE_DIGITAL_SIG);

	// Do the H-MAC
	wLen = wOutSize;
	if(tcSign(pIn,wInLen,pOut,&wLen) == 0)
		return wLen;
	
	outputMsg(stderr,"ERROR: mtlsHMAC(): Operation failed\n");
	return 0;
}

int mtlsEncryptDecryptOnly(unsigned char *pData, unsigned long dwDataLen, int sending, unsigned char *pIV) 
{
	unsigned char *pUseIv = pIV;
	unsigned short wLen;
	int status;

	//printf("mtlsEncryptDecryptOnly\n");

	// Set up the algo to use - only one supported at the moment
	tcMseSetAlgo(bCipherAlgo,TC_TEMPLATE_CONFIDENTIALITY);
				
	// Encrypt or decrypt?
	if(sending) // Encrypt
	{
		// Set the correct IV to use
		if(pUseIv == NULL)
			pUseIv = abClientIv;

		// Use client write key
		tcMseSetKeyFile(hCWK,TC_TEMPLATE_CONFIDENTIALITY);

		wLen = dwDataLen; 
		if(bCipherAlgo == TC_ALGO_AES_GCM)
		{
			wLen += GCM_TAG_LEN; // Assume space has been provided for the tag
			status = tcEncryptGcm(pData,dwDataLen,pUseIv,bCipherSuiteIvLen,abAdditionalData,wAdditionalDataLen,pData,&wLen);
		}
		else
			status = tcEncrypt(pData,dwDataLen,pUseIv,bCipherSuiteIvLen,pData,&wLen);

		if( status == 0 )
			return wLen;
		else
		{
			outputMsg(stderr,"ERROR: mtlsEncryptDecryptOnly(): Encryption failed\n");
			return(0);
		}
	}
	else // Decrypt
	{
		// Set the correct IV to use
		if(pUseIv == NULL)
			pUseIv = abServerIv;

		// Use server write key
		tcMseSetKeyFile(hSWK,TC_TEMPLATE_CONFIDENTIALITY);

		wLen = dwDataLen;
		if(bCipherAlgo == TC_ALGO_AES_GCM)
			status = tcDecryptGcm(pData,dwDataLen+GCM_TAG_LEN,pUseIv,bCipherSuiteIvLen,abAdditionalData,wAdditionalDataLen,pData,&wLen);
		else
			status = tcDecrypt(pData,dwDataLen,pUseIv,bCipherSuiteIvLen,pData,&wLen);
		if( status == 0 )
			return wLen;
		else
		{
			outputMsg(stderr,"ERROR: mtlsEncryptDecryptOnly(): Decryption failed\n");
			return(0);
		}
	}
}

unsigned short mtlsEncryptDecrypt(unsigned char *bSeqNum, unsigned char bContentType, unsigned short wProtocolVersion, unsigned short wDataLen, unsigned char *pData, int sending, unsigned char *pIV)
{
	unsigned char *pBuff;
	unsigned char *p;
	unsigned char abMac[SHA256_DIGEST_LEN]; //Longest it can be
	unsigned char abOrigMac[SHA256_DIGEST_LEN]; //Longest it can be
	unsigned short wBuffLen, wMacLen, wPlainLen, wCipherLen, wFragmentLen;
	unsigned char bPadLen;
	unsigned char abIV[CIPHERSUITE_MAX_BLOCK_LEN];
	int i,status;

	//printf("mtlsEncryptDecrypt\n");

	if(bCipherSuiteMacLen == 0)
	{
		outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): cannot be called with current ciphersuite\n");
		return 0;
	}

	// Encrypt or decrypt?
	if(sending) // Encrypt
	{
		// Format input to HASH-MAC into a buffer
		// seq_num || type || version || length || cleartext
		wBuffLen = wDataLen+13;
		pBuff = (unsigned char*)malloc(wBuffLen+128);
		if(pBuff == NULL)
		{
			outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): out of memory\n");
			return 0;
		}
		memcpy(pBuff,bSeqNum,8);
		pBuff[8] = bContentType;
		pBuff[9] = wProtocolVersion / 256;
		pBuff[10] = wProtocolVersion % 256;
		pBuff[11] = wDataLen / 256;
		pBuff[12] = wDataLen % 256;
		memcpy(pBuff+13,pData,wDataLen);

		// Generate the HASH-MAC with the client MAC key
		tcMseSetKeyFile(hCMK,TC_TEMPLATE_DIGITAL_SIG);
		if(bCipherSuiteMacLen == SHA256_DIGEST_LEN)
			tcMseSetAlgo(TC_ALGO_SHA256_HMAC,TC_TEMPLATE_DIGITAL_SIG);
		else
			tcMseSetAlgo(TC_ALGO_SHA1_HMAC,TC_TEMPLATE_DIGITAL_SIG);
		wMacLen = sizeof(abMac);
		if(tcSign(pBuff,wBuffLen,abMac,&wMacLen) == 0)
		{
			// Work out the amount of padding needed to pad the data to be encrypted
			bPadLen = bCipherSuiteBlockLen - ((wDataLen + wMacLen + 1) % bCipherSuiteBlockLen);

			// Resize buffer to put the data to encrypt into
			wBuffLen = wDataLen + wMacLen + bPadLen + 1;
			pBuff = (unsigned char*)realloc(pBuff,wBuffLen);
			if(pBuff == NULL)
			{
				outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): out of memory(2)\n");
				return 0;
			}

			// Build up the data to encrypt.
			// fragment || MAC || padding || padding_len
			
			p = pBuff;
			memcpy(p,pData,wDataLen);
			p += wDataLen;
			memcpy(p,abMac,wMacLen);
			p += wMacLen;
			for(i = 0; i < bPadLen; i++)
			{
				*p = bPadLen;
				p++;
			}
			*p = bPadLen;
			p++;
			wPlainLen = p - pBuff;

			// Get the random IV
			if(tcAskRandom(bCipherSuiteBlockLen,abIV))
			{
				// Copy back the IV
				memcpy(pIV,abIV,bCipherSuiteBlockLen);

				// Set the security environment with client write key
				tcMseSetAlgo(bCipherAlgo,TC_TEMPLATE_CONFIDENTIALITY);
				tcMseSetKeyFile(hCWK,TC_TEMPLATE_CONFIDENTIALITY);

				// Do the encryption
				wCipherLen = wPlainLen;
				status = tcEncrypt(pBuff,wPlainLen,pIV,bCipherSuiteIvLen,pData,&wCipherLen);
				if( status == 0 )
				{
					free(pBuff);
					return wCipherLen;
				}
				else
				{
					free(pBuff);
					outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): Encryption failed\n");
					return(0);
				}
			}
			else
			{
				free(pBuff);
				outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): Random IV generation failed\n");
				return(0);
			}
		}
		else
		{
			free(pBuff);
			outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): HMAC generation failed\n");
			return(0);
		}
	}
	else // Decrypt
	{
		// Allocate some space for the decrypted message
		pBuff = (unsigned char*)malloc(wDataLen);
		if(pBuff == NULL)
		{
			outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): out of memory\n");
			return 0;
		}

		// Decrypt message using server write key and provided IV
		tcMseSetKeyFile(hSWK,TC_TEMPLATE_CONFIDENTIALITY);
		tcMseSetAlgo(bCipherAlgo,TC_TEMPLATE_CONFIDENTIALITY);

		wPlainLen = wDataLen;
		status = tcDecrypt(pData,wDataLen,pIV,bCipherSuiteIvLen,pBuff,&wPlainLen);
		if( status == 0)
		{
			// Check the padding is valid
			bPadLen = pBuff[wPlainLen-1];
			if(bPadLen > wPlainLen) // ... first the padding length looks reasonable
			{
				free(pBuff);
				outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): Decryption - incorrect padding length\n");
				return(0);
			}
			p = pBuff + wPlainLen - 1 - bPadLen; // ... then the padding characters are all the correct value
			for(i = 0; i < bPadLen; i++)
			{
				if(*p != bPadLen)
				{
					free(pBuff);
					outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): Decryption - incorrect padding\n");
					return(0);
				}
				p++;
			}

			// Work out the length of the clear fragment of data contained in the decrypted message
			wFragmentLen = wDataLen - 1 - bPadLen - bCipherSuiteMacLen;

			// Save the MAC to compare later
			// seq_num || type || version || fragment length || clear fragment
			memcpy(abOrigMac,pBuff+wFragmentLen,bCipherSuiteMacLen);

			// Build the MAC data into a buffer
			p = (unsigned char*) malloc (13 + wFragmentLen);
			if(p == NULL)
			{
				outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): out of memory\n");
				return 0;
			}			
			memcpy(p,bSeqNum,8);
			p += 8;
			*p = bContentType;
			p++;
			*p = wProtocolVersion / 256;
			p++;
			*p = wProtocolVersion % 256;
			p++;
			*p = wFragmentLen / 256;
			p++;
			*p = wFragmentLen % 256;
			p++;
			memcpy(p,pBuff,wFragmentLen);
			p += wFragmentLen;

			// Calculate the MAC using the server mac key
			tcMseSetKeyFile(hSMK,TC_TEMPLATE_DIGITAL_SIG);
			if(bCipherSuiteMacLen == SHA256_DIGEST_LEN)
				tcMseSetAlgo(TC_ALGO_SHA256_HMAC,TC_TEMPLATE_DIGITAL_SIG);
			else
				tcMseSetAlgo(TC_ALGO_SHA1_HMAC,TC_TEMPLATE_DIGITAL_SIG);
			wMacLen = sizeof(abMac);
			if(tcSign(p,13 + wFragmentLen,abMac,&wMacLen) == 0)
			{
				// Compare calculated MAC to provided MAC
				if(memcmp(abOrigMac,abMac,wMacLen) == 0)
				{
					// All good. Return the clear text
					memcpy(pData,pBuff,wFragmentLen);
					free(p);
					free(pBuff);
					return(wFragmentLen);
				}
				else
				{
					free(pBuff);
					free(p);
					outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): HMAC comparison failed\n");
					return(0);
				}
			}
			else
			{
				free(pBuff);
				free(p);
				outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): HMAC failed\n");
				return(0);
			}
		}
		else
		{
			free(pBuff);
			outputMsg(stderr,"ERROR: mtlsEncryptDecrypt(): Decryption failed\n");
			return(0);
		}
	}
}

unsigned short mtlsGenerateFinalFinishMAC(char *sLabel, unsigned char *abHandShakeHash, unsigned short wHashLen, unsigned char *pOut,  unsigned short wOutSize)
{
	unsigned short wLen;

	// Out buffer needs to be at least 12 bytes long
	if(wOutSize < 12)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateFinalFinishMAC(): Output buffer needs to be at least 12 bytes long\n");
		return 0;
	}

	// Hash length can't exceed 32
	if(wHashLen > 32)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateFinalFinishMAC(): 'wHashLen' value too large (%d, max is 32)\n",wHashLen);
		return 0;
	}

	// Set up template
	tcMseSetKeyFile(hMS,TC_TEMPLATE_DIGITAL_SIG);
	if(strcmp(sLabel,"server finished") == 0)
		tcMseSetAlgo(TC_ALGO_TLS12_MAC_SERVER,TC_TEMPLATE_DIGITAL_SIG);
	else if (strcmp(sLabel,"client finished") == 0)
		tcMseSetAlgo(TC_ALGO_TLS12_MAC_CLIENT,TC_TEMPLATE_DIGITAL_SIG);
	else
	{
		outputMsg(stderr,"ERROR: mtlsGenerateFinalFinishMAC(): invalid label\n");
		return 0;
	}
	wLen = wOutSize;
	if (tcSign(abHandShakeHash,wHashLen,pOut,&wLen) == 0)
		return wLen;
	else
	{
		outputMsg(stderr,"ERROR: mtlsGenerateFinalFinishMAC(): signature operation failed\n");
		return 0;
	}
}

int mtlsGenerateClientRandom(unsigned long dwServerTime, unsigned char bUseTime, unsigned char *pOut,  unsigned short wOutSize)
{
	if(wOutSize < TLS_RANDOM_LEN)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateClientRandom(): Supplied buffer too small\n");
		return 0;
	}

	if (tcAskRandom(TLS_RANDOM_LEN,abClientRandom))
	{
		if(bUseTime)
		{
			abClientRandom[0] = dwServerTime / (256*256*256);
			abClientRandom[1] = dwServerTime / (256*256);
			abClientRandom[2] = dwServerTime / 256;
			abClientRandom[3] = dwServerTime % 256;
		}
		memcpy(pOut,abClientRandom,TLS_RANDOM_LEN);
		return TLS_RANDOM_LEN;
	}
	else
		return 0;
}

// Returns the length of the encrypted pre-master secret (RSA), 1 (ECDH success) or 0 (failure)
unsigned short mtlsGeneratePreMasterSecret(unsigned char bMajor, unsigned char bMinor, unsigned char *pPubKey, unsigned short wPubKeyLen, unsigned char *pExponent, unsigned char bExpLen, unsigned char *pOut,  unsigned short wOutSize)
{
	unsigned long len = 0;

	if(bEcdheMode)
	{
		// Set up the template to do ECDH with the ephemeral key
		tcMseSetKeyFile(EPHEMERAL_KEY_HANDLE,TC_TEMPLATE_TLS);
		tcMseSetAlgo(TC_ALGO_ECDH1,TC_TEMPLATE_TLS);

		len = tcGeneratePreMasterSecretAlgo(pPubKey,wPubKeyLen,&hPMS);

		if(len == 0)
			outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): key generation function failed\n");
	}
	else
	{
		// bExpLen is a maximum of 3 bytes
		if(bExpLen > 3)
		{
			outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): Exponent length too long (maximum is 3)\n");
			return 0;
		}

		if(wOutSize < wPubKeyLen)
		{
			outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): supplied buffer too small\n");
			return 0;
		}

		// Preload the untrusted public key
		if(!tcLoadUntrustedPublicKey(pPubKey,wPubKeyLen,pExponent,bExpLen))
		{
			outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): failed to load public key\n");
			return 0;
		}

		// Generate the pre master secret
		if (tcGeneratePreMasterSecret(bMajor,bMinor,&hPMS) )
		{
			// Wrap it using the preloaded public key
			tcMseSetAlgo(TC_ALGO_RSA,TC_TEMPLATE_CONFIDENTIALITY);

			len = wOutSize;
			if (!tcWrapKey(hPMS,pOut,&len))
			{
				outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): key wrap function failed\n");
				return 0;
			}
		}
		else
		{
			outputMsg(stderr,"ERROR: mtlsGeneratePreMasterSecret(): key generation function failed\n");
			return 0;
		}
	}
	return len;
}

int mtlsGenerateMasterSecret(unsigned char *pServerRandom)
{
	unsigned char abBuff[TLS_RANDOM_LEN * 2];
	unsigned char bMaj,bMin;

	// Assemble randoms in correct order
	memcpy(abBuff,abClientRandom,TLS_RANDOM_LEN);
	memcpy(abBuff+TLS_RANDOM_LEN,pServerRandom,TLS_RANDOM_LEN);

	// Save the server random for later use
	memcpy(abServerRandom,pServerRandom,TLS_RANDOM_LEN);

	// Generate the master secret
	if(!tcGenerateMasterSecret(hPMS,FALSE,abBuff,TLS_RANDOM_LEN*2,&hMS,&bMaj,&bMin))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateMasterSecret(): function failed\n");
		return 0;
	}
	return 1;
}

int mtlsGenerateMasterSecretExtended(unsigned char *abHandShakeHash, unsigned short wHashLen, unsigned char *pServerRandom)
{
	unsigned char bMaj,bMin;

	if(wHashLen != 32)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateMasterSecretExtended(): Handshake hash length must be 32 bytes\n");
		return 0;
	}

	// Save the server random for later use
	memcpy(abServerRandom,pServerRandom,TLS_RANDOM_LEN);

	// Generate the master secret
	if(!tcGenerateMasterSecret(hPMS,TRUE,abHandShakeHash,wHashLen,&hMS,&bMaj,&bMin))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateMasterSecretExtended(): function failed\n");
		return 0;
	}
	return 1;
}

int mtlsGenerateKeys(unsigned char **pClientIvPtr, unsigned char **pServerIvPtr)
{
	unsigned char abBuff[TLS_RANDOM_LEN * 2];
	int ret = 0;

	// Assemble randoms in correct order
	memcpy(abBuff,abServerRandom,TLS_RANDOM_LEN);
	memcpy(abBuff+TLS_RANDOM_LEN,abClientRandom,TLS_RANDOM_LEN);

	// Set up the TLS template in the security environment
	tcMseSetKeyFile(hMS,TC_TEMPLATE_TLS);

	// Clear the old iv values
	memset(abClientIv,0,sizeof(abClientIv));
	memset(abServerIv,0,sizeof(abServerIv));

	// Finally generate the keys.
	ret = tcGenerateSessionKeys(abBuff,&hCMK,&hSMK,&hCWK,&hSWK,abClientIv,abServerIv);

	// Let the caller know where to find the IVs in case it wants to use them
	*pClientIvPtr = abClientIv;
	*pServerIvPtr = abServerIv;

	return ret;
}

// Verify a signature that is RSA / SHA256 based
int mtlsRsaVerifySignature(unsigned char *pModulus, unsigned short wModLen, unsigned char *pExponent, unsigned char bExpLen, unsigned char *pData, unsigned short wDataLen, unsigned char *pSignature)
{
	int result = 0;
	unsigned char abHash[32];

	// bExpLen is a maximum of 3 bytes
	if(bExpLen > 3)
	{
		outputMsg(stderr,"ERROR: mtlsRsaVerifySignature(): Exponent length too long (maximum is 3)\n");
		return 0;
	}

	// Set security environment
	tcMseSetAlgo(TC_ALGO_RSA,TC_TEMPLATE_DIGITAL_SIG);

	// Upload the public key to the app as an untrusted key
	if(!tcLoadUntrustedPublicKey(pModulus,wModLen,pExponent,bExpLen))
	{
		outputMsg(stderr,"ERROR: mtlsRsaVerifySignature(): failed to load public key\n");
		return 0;
	}

	// Decrypt the signature (in place)
	if(tcVerify(pSignature,wModLen) == 0)
	{
		// The hash is in the last 32 bytes
		pSignature = pSignature + wModLen - SHA256_DIGEST_LEN;

		// Call MULTOS to hash the provided data
		mtlsSha256Init();
		mtlsSha256Update(pData,wDataLen);
		mtlsSha256Final(abHash);

		// Compare the computed hash against the recovered hash
		result = memcmp(pSignature,abHash,SHA256_DIGEST_LEN) == 0 ? 1 : 0;		
	}
	else
		outputMsg(stderr,"WARNING: mtlsRsaVerifySignature(): signature decryption failed\n");

	return result;
}

// Assumes 2048 bit MULTOS device key
int mtlsRsaSignPKCS1_type1(unsigned char *pData, unsigned short wDataLen, unsigned char bDoHash, unsigned char **pOutPtr)
{
	unsigned char *p;
	int len = 0;
	int signStatus;
	unsigned short wSigLen;

	//printf("mtlsRsaSignPKCS1_type1()\n");

	// Create working buffer the size of the RSA public key. Caller to free pointer when finished with it
	p = (unsigned char *)malloc(DEVICE_KEY_LEN);
	if(p == NULL)
	{
		outputMsg(stderr,"ERROR: mtlsRsaSignPKCS1_type1(): out of memory\n");
		return 0;
	}
	
	// If the data is already hashed, it must be the correct length
	if(!bDoHash && wDataLen != SHA256_DIGEST_LEN)
	{
		outputMsg(stderr,"ERROR: mtlsRsaSignPKCS1_type1(): data length should be %d if already hashed\n",SHA256_DIGEST_LEN);
		return 0;
	}

	// Copy in the signature template
	memcpy(p,abSha256SigTemplate,sizeof(abSha256SigTemplate));

	if(bDoHash)
	{
		//printf("...calculating hash\n");

		// SHA256 the data directly into the template
		mtlsSha256Init();
		mtlsSha256Update(pData,wDataLen);
		mtlsSha256Final(p+sizeof(abSha256SigTemplate)-SHA256_DIGEST_LEN);
	}
	else
	{
		//printf("...supplied hash\n");

		// Use supplied hash
		memcpy(p+sizeof(abSha256SigTemplate)-SHA256_DIGEST_LEN,pData,wDataLen);
	}

	// Set up the security environment. Assumes the device key is in slot 0
	tcMseSetAlgo(TC_ALGO_RSA,TC_TEMPLATE_DIGITAL_SIG);
	tcMseSetKeyFile(TC_EF_PRIVKEY_1,TC_TEMPLATE_DIGITAL_SIG);

	// Call MULTOS to sign - output to the same buffer as the input
	len = 0;
	wSigLen = DEVICE_KEY_LEN;
	signStatus = tcSign(p,sizeof(abSha256SigTemplate),p,&wSigLen);
	//printf("...sign status=%d\n",signStatus);
	if ( signStatus == 0)
	{
		len = wSigLen;
	}
	*pOutPtr = p;

	//printf("... siglen=%d\n",len);
	return len;
}

int mtlsRsaSignPKCS1_PSS(unsigned char *pData, unsigned short wDataLen, unsigned char bDoHash, unsigned char **pOutPtr)
{
	unsigned short wSigLen;
	unsigned char *p;
	int len;

	//printf("mtlsRsaSignPKCS1_PSS()\n");
	// Create working buffer the size of the RSA public key. Caller to free pointer when finished with it
	p = (unsigned char *)malloc(DEVICE_KEY_LEN);
	if(p == NULL)
	{
		outputMsg(stderr,"ERROR: mtlsRsaSignPKCS1_PSS(): out of memory\n");
		return 0;
	}

	// If the data is already hashed, it must be the correct length
	if(!bDoHash && wDataLen != SHA256_DIGEST_LEN)
	{
		outputMsg(stderr,"ERROR: mtlsRsaSignPKCS1_PSS(): data length should be %d if already hashed\n",SHA256_DIGEST_LEN);
		return 0;
	}

	if(bDoHash)
	{
		// Hash the data (using MULTOS)
		mtlsSha256Init();
		mtlsSha256Update(pData,wDataLen);
		mtlsSha256Final(p);
	}
	else
		memcpy(p,pData,wDataLen); // Use the hash provided

	// Set up the security environment. Assumes the device key is in slot 0
	tcMseSetAlgo(TC_ALGO_PSS_SHA256,TC_TEMPLATE_DIGITAL_SIG);
	tcMseSetKeyFile(TC_EF_PRIVKEY_1,TC_TEMPLATE_DIGITAL_SIG);

	// Call MULTOS to sign
	len = 0;
	wSigLen = DEVICE_KEY_LEN;
	if(tcSign(p,SHA256_DIGEST_LEN,p,&wSigLen) == 0)
		len = wSigLen;	
	*pOutPtr = p;

	return len;
}

#define MAX_RAND_SIZE 248
int mtlsGenerateRandom(unsigned short len, unsigned char *pOut)
{
	int numCalls = len / MAX_RAND_SIZE;
	int numBytesRemain = len % MAX_RAND_SIZE;
	int i;
	unsigned char abRandBlock[MAX_RAND_SIZE];

	for(i = 0; i < numCalls; i++)
	{
		if(!tcAskRandom(MAX_RAND_SIZE,pOut+(i*MAX_RAND_SIZE)) )
		{
			outputMsg(stderr,"ERROR: mtlsGenerateRandom(): random data generation failed\n");
			return 0;			
		}
	}
	if(numBytesRemain)
	{
		if(!tcAskRandom(numBytesRemain,abRandBlock) )
		{
			outputMsg(stderr,"ERROR: mtlsGenerateRandom(): random data generation failed\n");
			return 0;			
		}
		memcpy(pOut+(i*MAX_RAND_SIZE),abRandBlock,numBytesRemain);
	}
	return 1;
}

int mtlsGenerateRsaKeyPair(char *sFileName, char *sCountryName, char *sStateOrProvinceName, char *sLocalityName, char *sOrgName, char *sOrgUnit, char *sCommonName, char *sEmailAddress)
{
	char acPinData[TC_PIN_SIZE];
	int i;

	unsigned short wPubKeySeqLen = 0;

	unsigned char abCNSet[128];
	unsigned char bCNLen;
	unsigned char abSTSet[128];
	unsigned char bSTLen;
	unsigned char abLOSet[128];
	unsigned char bLOLen;
	unsigned char abORSet[128];
	unsigned char bORLen;
	unsigned char abOUSet[128];
	unsigned char bOULen;
	unsigned char abCMSet[128];
	unsigned char bCMLen;
	unsigned char abEMSet[128];
	unsigned char bEMLen;

	unsigned char abInfoSeq[7*128 + 4];
	unsigned short wInfoSeqLen = 0;

	unsigned char abSigData[1024];
	unsigned short wSigDataLen = 0;
	unsigned char *pSignature;
	unsigned short wSigLen = 0;

	unsigned char abFullSeq[1024];
	unsigned short wSeqLen = 0;

	char sCertRequest[2048];
	unsigned short wCertReqLen = 0;

	FILE *fp;
	unsigned short w;

	// Generate the Certificate Information sequence from the input parameters
	bCNLen = asn1MakeSet(OID_CN,sizeof(OID_CN),ASN1_PrintableString,sCountryName,abCNSet);
	bSTLen = asn1MakeSet(OID_ST,sizeof(OID_ST),ASN1_UTF8String,sStateOrProvinceName,abSTSet);
	bLOLen = asn1MakeSet(OID_LO,sizeof(OID_LO),ASN1_UTF8String,sLocalityName,abLOSet);
	bORLen = asn1MakeSet(OID_OR,sizeof(OID_OR),ASN1_UTF8String,sOrgName,abORSet);
	bOULen = asn1MakeSet(OID_OU,sizeof(OID_OU),ASN1_UTF8String,sOrgUnit,abOUSet);
	bCMLen = asn1MakeSet(OID_CM,sizeof(OID_CM),ASN1_UTF8String,sCommonName,abCMSet);
	bEMLen = asn1MakeSet(OID_EM,sizeof(OID_EM),ASN1_IA5String,sEmailAddress,abEMSet);
	wInfoSeqLen = bCNLen + bSTLen + bLOLen + bORLen + bOULen + bCMLen + bEMLen;
	if(wInfoSeqLen+4 > sizeof(abInfoSeq))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Certificate info sequence too long\n");
		return 0;
	}
	w = 0;
	abInfoSeq[w++] = ASN1_SEQ;
	if(wInfoSeqLen < 128)
	{
		abInfoSeq[w++] = wInfoSeqLen;
	}
	else if (wInfoSeqLen < 256)
	{
		abInfoSeq[w++] = 0x81;
		abInfoSeq[w++] = wInfoSeqLen;
	}
	else
	{
		abInfoSeq[w++] = 0x82;
		abInfoSeq[w++] = wInfoSeqLen / 256;
		abInfoSeq[w++] = wInfoSeqLen % 256;
	}
	memcpy(abInfoSeq+w,abCNSet,bCNLen);
	w += bCNLen;
	memcpy(abInfoSeq+w,abSTSet,bSTLen);
	w += bSTLen;
	memcpy(abInfoSeq+w,abLOSet,bLOLen);
	w += bLOLen;
	memcpy(abInfoSeq+w,abORSet,bORLen);
	w += bORLen;
	memcpy(abInfoSeq+w,abOUSet,bOULen);
	w += bOULen;
	memcpy(abInfoSeq+w,abCMSet,bCMLen);
	w += bCMLen;
	memcpy(abInfoSeq+w,abEMSet,bEMLen);
	w += bEMLen;
	wInfoSeqLen = w;

	// Log in with key management pin
	// Load the PIN from the file
	memset(acPinData,0xFF,sizeof(acPinData));
	fp = fopen("keyman_pin.txt","r");
	if(fp == NULL)
	{
		outputMsg(stderr,"WARNING: mtlsGenerateRsaKeyPair(): Failed to open keyman_pin.txt. Using 1234\n");
		acPinData[0] = '1';
		acPinData[1] = '2';
		acPinData[2] = '3';
		acPinData[3] = '4';
	}
	else
	{
		fgets(acPinData,sizeof(acPinData),fp);
		fclose(fp);

		// Remove NULL and possible newline characters 0x0D and 0x0A
		for(i = strlen(acPinData); i >= 0 && (acPinData[i] == 0x0A || acPinData[i] == 0x0D || acPinData[i] == 0x00); i--)
			acPinData[i] = 0xFF;
	}
	if(!tcVerifyPIN2(TC_PINREF_K,(CK_BYTE*)acPinData))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Failed to log in with key management PIN\n");
		return 0;
	}

	// Call MULTOS - get ASN.1 formatted public key
	if(tcGenerateRsaKey(0x6100,DEVICE_KEY_LEN*8) != 0)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Key generation failed\n");
		return 0;
	}

	wPubKeySeqLen = sizeof(devicePubKey);
	if(tcReadRsaModulus(0x6100,((BYTE*)&devicePubKey)+33,sizeof(devicePubKey)-33) == 0)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Failed to get public key\n");
		return 0;
	}

	// Combine the info and key sequences into the sequence to be signed
	w = 0;
	wSigDataLen = wInfoSeqLen + wPubKeySeqLen + 3 + 2;
	if(wSigDataLen + 4 > sizeof(abSigData))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Signed sequence too long\n");
		return 0;
	}
	abSigData[w++] = ASN1_SEQ;
	if(wSigDataLen < 128)
	{
		abSigData[w++] = wSigDataLen;
	}
	else if (wSigDataLen < 256)
	{
		abSigData[w++] = 0x81;
		abSigData[w++] = wSigDataLen;
	}
	else
	{
		abSigData[w++] = 0x82;
		abSigData[w++] = wSigDataLen / 256;
		abSigData[w++] = wSigDataLen % 256;
	}
	abSigData[w++] = ASN1_INT; //INTEGER 0 sequence element
	abSigData[w++] = 1;
	abSigData[w++] = 0;
	memcpy(abSigData+w,abInfoSeq,wInfoSeqLen); // SEQUENCE - 7 elements
	w += wInfoSeqLen;
	memcpy(abSigData+w,&devicePubKey,wPubKeySeqLen); // SEQUENCE - 2 elements
	w += wPubKeySeqLen;
	abSigData[w++] = ASN1_ZERO;
	abSigData[w++] = 0;
	wSigDataLen = w;

	// Sign the request sequence using MULTOS
	wSigLen = mtlsRsaSignPKCS1_type1(abSigData,wSigDataLen,1,&pSignature);
	if (wSigLen == 0)
		return 0;

	// Contruct full CSR sequence
	wSeqLen = wSigDataLen + sizeof(ASN1_SEQ_SIGN_METHOD) + 5 + DEVICE_KEY_LEN;
	if(wSeqLen + 4 > sizeof(abFullSeq))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): CSR sequence too long\n");
		free(pSignature);
		return 0;
	}
	w = 0;
	abFullSeq[w++] = ASN1_SEQ;
	if(wSeqLen < 128)
	{
		abFullSeq[w++] = wSeqLen;
	}
	else if (wSeqLen < 256)
	{
		abFullSeq[w++] = 0x81;
		abFullSeq[w++] = wSeqLen;
	}
	else
	{
		abFullSeq[w++] = 0x82;
		abFullSeq[w++] = wSeqLen / 256;
		abFullSeq[w++] = wSeqLen % 256;
	}
	memcpy(abFullSeq+w,abSigData,wSigDataLen);
	w += wSigDataLen;
	memcpy(abFullSeq+w,ASN1_SEQ_SIGN_METHOD,sizeof(ASN1_SEQ_SIGN_METHOD));
	w += sizeof(ASN1_SEQ_SIGN_METHOD);
	abFullSeq[w++] = ASN1_BitString;
	abFullSeq[w++] = 0x82;
	abFullSeq[w++] = (wSigLen+1) / 256;
	abFullSeq[w++] = (wSigLen+1) % 256;
	abFullSeq[w++] = 0x00; // Extra byte to ensure not negative signed number
	memcpy(abFullSeq + w, pSignature, wSigLen);
	w += wSigLen;
	wSeqLen = w;
	free(pSignature);

	// Convert to Base64
	memset(sCertRequest,0,sizeof(sCertRequest));
	base64Encode(abFullSeq,wSeqLen,&wCertReqLen,sCertRequest);

	// Output to PEM file with necessary header and trailer
	fp = fopen(sFileName,"w");
	if(!fp)
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Failed to open PEM file %s\n",sFileName);
		return 0;
	}
	fprintf(fp,"-----BEGIN CERTIFICATE REQUEST-----\n");
	fprintf(fp,"%s",sCertRequest);
	fprintf(fp,"\n-----END CERTIFICATE REQUEST-----\n");
	fclose(fp);

	// Revert to the user pin
	// Load the PIN from the file
	memset(acPinData,0xFF,sizeof(acPinData));
	fp = fopen("user_pin.txt","r");
	if(fp == NULL)
	{
		outputMsg(stderr,"WARNING: mtlsGenerateRsaKeyPair(): Failed to open user_pin.txt. Using 1234\n");
		acPinData[0] = '1';
		acPinData[1] = '2';
		acPinData[2] = '3';
		acPinData[3] = '4';
	}
	else
	{
		fgets(acPinData,sizeof(acPinData),fp);
		fclose(fp);

		// Remove NULL and possible newline characters 0x0D and 0x0A
		for(i = strlen(acPinData); i >= 0 && (acPinData[i] == 0x0A || acPinData[i] == 0x0D || acPinData[i] == 0x00); i--)
			acPinData[i] = 0xFF;
	}
	if(!tcVerifyPIN2(TC_PINREF_G,(CK_BYTE*)acPinData))
	{
		outputMsg(stderr,"ERROR: mtlsGenerateRsaKeyPair(): Failed to log in with user PIN\n");
		return 0;
	}

	return 1; //OK
}

int mtlsECDSASign(unsigned char *pHash, unsigned short wHashLen, unsigned char *pSignature)
{
	unsigned short wSigLen;
	int len = 0;

	//printf("mtlsECDSASign()\n");

	// Set up the security environment. Assumes the device key is in slot 0
	tcMseSetAlgo(TC_ALGO_ECDSA,TC_TEMPLATE_DIGITAL_SIG);
	tcMseSetKeyFile(TC_EFTYPE_EC_PRIVKEY,TC_TEMPLATE_DIGITAL_SIG);

	// Call MULTOS to sign
	wSigLen = 132; // Assume the buffer provided is big enough
	if(tcSign(pHash,wHashLen,pSignature,&wSigLen) == 0)
		len = wSigLen;
	else
		outputMsg(stderr,"ERROR: mtlsECDSASign(): signature failed\n");

	return len;
}

int mtlsECDSAVerify(unsigned char *pPubKey, unsigned short wPubKeyLen, unsigned char bNamedCurve, unsigned char *pData, unsigned short wDataLen, unsigned char *pSignature)
{
	int result = 0;
	unsigned char abHash[66]; // SHA-512 biggest size
	unsigned char *pHash = abHash; // Default to SHA-256
	unsigned char bHashLen = 32;
	unsigned char bExtraLen = 0;

	// Set security environment
	tcMseSetAlgo(TC_ALGO_ECDSA,TC_TEMPLATE_DIGITAL_SIG);

	// Upload the public key to the app as an untrusted key
	if(!tcLoadUntrustedPublicEccKey(bNamedCurve,pPubKey,wPubKeyLen))
	{
		outputMsg(stderr,"ERROR: mtlsECDSAVerify(): failed to load public key\n");
		return 0;
	}

	// Set hash length according to named curve (default is SHA-256)
	if(bNamedCurve == TC_NAMED_CURVE_P384)
		bHashLen = 48;
	else if (bNamedCurve == TC_NAMED_CURVE_P521)
	{
		abHash[0] = 0;
		abHash[1] = 0;
		pHash = abHash + 2;
		bHashLen = 64;
		bExtraLen = 2;
	}
	
	// Hash the data
	if(!tcShaInit(bHashLen))
	{
		outputMsg(stderr,"ERROR: mtlsECDSAVerify(): hash initialisation failed\n");
		return 0;
	}
	tcShaUpdate(pData,wDataLen);
	tcShaFinal(pHash);

	// Then verify the signature
	result = (tcVerifyECDSA(abHash,bHashLen + bExtraLen,pSignature,wPubKeyLen) == 0);

	return result;
}

int mtlsGenerateEphemeralECKey(unsigned char bNamedCurve,unsigned char *pPubKey)
{
	return tcGenerateEcKey(EPHEMERAL_KEY_HANDLE,bNamedCurve,1,pPubKey);
}

int mtlsSetAdditionalData(unsigned char *pData, unsigned short wDataLen)
{
	if(wDataLen > MAX_ADDN_DATA_LEN)
		return 0;

	memcpy(abAdditionalData,pData,wDataLen);
	wAdditionalDataLen = wDataLen;
	return 1;
}

