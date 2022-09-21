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
 *      Implements an APDU abstraction layer for Trust Core app
 */


#include "tc_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int tcSelectApp()
{
	int selected = multosSelectApplication((char*)TC_AID);
	return selected;
}

// Verify PIN when you have the PKCS#11 USER_TYPE
// If pbVerificationData is NULL, then this function returns the remaining number of PIN tries (or -1 on error)
// Otherwise it returns 1 for successful PIN verification, 0 otherwise.
int
tcVerifyPIN(CK_USER_TYPE userId, BYTE *pbVerificationData)
{
	WORD SW12;
	WORD La;
	BYTE bPINRef = TC_PINREF_G;
	BYTE dummy[4];

	if(userId == CKU_SO)
		bPINRef = TC_PINREF_SO;
	else if (userId == CKU_CONTEXT_SPECIFIC)
		bPINRef = TC_PINREF_K;

	if(pbVerificationData)
	{
		SW12 = multosSendAPDU(0x80, TC_INS_VERIFY, 0x00, bPINRef, TC_PIN_SIZE, 0, &La, TC_NOTCASE4_INS, pbVerificationData,TC_PIN_SIZE,TC_MAX_APDU_WAIT);
		return SW12 == 0x9000;
	}
	else
	{
		SW12 = multosSendAPDU(0x80, TC_INS_VERIFY, 0x00, bPINRef, 0x00, 0, &La, TC_NOTCASE4_INS, dummy,4,TC_MAX_APDU_WAIT);
		if((SW12 & 0x63C0) == 0x63C0)
			return (int)(SW12 ^ 0x63C0);
		else
			return -1;
	}
}

// Verify PIN when you have the TC PIN Reference
// If pbVerificationData is NULL, then this function returns the remaining number of PIN tries (or -1 on error)
// Otherwise it returns 1 for successful PIN verification, 0 otherwise.
int
tcVerifyPIN2(CK_BYTE bPINRef , CK_BYTE *pbVerificationData)
{
	WORD SW12;
	WORD La;
	CK_BYTE dummy[4];

	if(pbVerificationData)
	{
		SW12 = multosSendAPDU(0x80, TC_INS_VERIFY, 0x00, bPINRef, TC_PIN_SIZE, 0, &La, TC_NOTCASE4_INS, pbVerificationData,TC_PIN_SIZE,TC_MAX_APDU_WAIT);
		return SW12 == 0x9000;
	}
	else
	{
		SW12 = multosSendAPDU(0x80, TC_INS_VERIFY, 0x00, bPINRef, 0x00, 0, &La, TC_NOTCASE4_INS, dummy,4,TC_MAX_APDU_WAIT);
		if((SW12 & 0x63C0) == 0x63C0)
			return (int)(SW12 ^ 0x63C0);
		else
			return -1;
	}
}

// Change PIN when you have the TC pin reference
int
tcChangePIN(CK_BYTE bPinRef, CK_BYTE_PTR pSoPIN, CK_BYTE_PTR pNewPIN)
{
	WORD SW12;
	WORD La;
	CK_BYTE data[TC_PIN_SIZE*2];

	memcpy(data,pSoPIN,TC_PIN_SIZE);
	memcpy(data+TC_PIN_SIZE,pNewPIN,TC_PIN_SIZE);
	SW12 = multosSendAPDU(0x80, TC_INS_CHANGE, 0x00, bPinRef, sizeof(data), 0, &La, TC_NOTCASE4_INS, data,sizeof(data),TC_MAX_APDU_WAIT);
	return SW12 == 0x9000;
}

// Change PIN when you have the PKCS#11 user type
int
tcSetPINSOLoggedIn(CK_USER_TYPE userId, BYTE *pbNewPin)
{
	WORD SW12;
	WORD La;
	BYTE bPINRef = TC_PINREF_G;

	if(userId == CKU_SO)
		bPINRef = TC_PINREF_SO;
	else if (userId == CKU_CONTEXT_SPECIFIC)
		bPINRef = TC_PINREF_K;

	SW12 = multosSendAPDU(0x80, TC_INS_CHANGE, 0x00, bPINRef, TC_PIN_SIZE, 0, &La, TC_NOTCASE4_INS, pbNewPin,TC_PIN_SIZE,TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

// Change PIN when you have the PKCS#11 user type
int
tcSetPIN(CK_USER_TYPE userId, BYTE *pbVerificationData, BYTE *pbNewPin)
{
	WORD SW12;
	WORD La;
	BYTE pinData[TC_PIN_SIZE*2];
	BYTE bPINRef = TC_PINREF_G;

	if(userId == CKU_SO)
		bPINRef = TC_PINREF_SO;
	else if (userId == CKU_CONTEXT_SPECIFIC)
		bPINRef = TC_PINREF_K;

	memcpy(pinData,pbVerificationData,TC_PIN_SIZE);
	memcpy(pinData+TC_PIN_SIZE,pbNewPin,TC_PIN_SIZE);

	SW12 = multosSendAPDU(0x80, TC_INS_REF_DATA, 0x00, bPINRef, TC_PIN_SIZE*2, 0, &La, TC_NOTCASE4_INS, pinData,TC_PIN_SIZE*2,TC_MAX_APDU_WAIT);

	memset(pinData,0,TC_PIN_SIZE*2);

	return SW12 == 0x9000;
}

int tcSelectEF(WORD wEFId, WORD *pwFileSize)
{
	WORD SW12;
	WORD La;
	BYTE data[4];

	// Ensure EFId is written as big endian data
	data[0] = wEFId / 256;
	data[1] = wEFId % 256;

	SW12 = multosSendAPDU(0x80, 0xA4, 0x00, 0x00, 0x02, 0x04, &La, TC_CASE4_INS, data,sizeof(data), TC_MAX_APDU_WAIT);
	//printf("EFID %04x, SW %04x\n",wEFId,SW12);

	if(SW12 == 0x9000 && La == 4)
	{
		*pwFileSize = data[2] * 256 + data[3];
		return 1;
	}
	return 0;
}

int tcWriteCurrentEF(WORD wOffset, BYTE bNumBytes, BYTE *pBuffer)
{
	BYTE P1,P2;
	WORD SW12;
	WORD La;

	P1 = wOffset / 256;
	P2 = wOffset % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_UPD_BINARY, P1, P2, bNumBytes, 0, &La, TC_NOTCASE4_INS, pBuffer, bNumBytes, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcErasePrivateKey(WORD wEFId)
{
	WORD fileSize;
	BYTE buffer[] = { 0x00, 0x00 };

	// Select file
	if(tcSelectEF(wEFId,&fileSize))
	{
		// Write 2 bytes of zeros, causes file to be erased and put into update mode
		return tcWriteCurrentEF(0,2,buffer);
	}
	return 0;
}

// Returns:
// 0: OK
// 1: No space
// 2: Permission error
// 3: Other error
int tcCreateEF(BYTE bPrefix, BYTE bMaxSuffix, WORD wSize, DWORD dwReadAccess, DWORD dwUpdateAccess, WORD *pwEFId)
{
	WORD efId;
	WORD fileSize;
	BYTE i = 0;
	WORD SW12;
	BYTE data[14];
	WORD La;

	if(dwReadAccess > 0x0F)
		return 2;

	if(dwUpdateAccess > 0x0F)
		return 2;

	// Loop until an unused EFId is found
	while(i <= bMaxSuffix)
	{
		efId = bPrefix * 256 + i;
		if(tcSelectEF(efId,&fileSize))
		{
			// Reselect DF
			//tcSelectApp();

			// Try next EFId
			i++;
		}
		else
			// Spare EF found. Break out
			break;
	}

	// If found
	if(i <= bMaxSuffix)
	{
		// Create the file, or try to
		data[0] = 0;
		data[1] = efId / 256;
		data[2] = efId % 256;
		data[3] = wSize / 256;
		data[4] = wSize % 256;
		data[5] = 0;
		data[6] = 0;
		data[7] = 0;
		data[8] = dwReadAccess;
		data[9] = 0;
		data[10] = 0;
		data[11] = 0;
		data[12] = dwUpdateAccess;
		data[13] = 0;

		SW12 = multosSendAPDU(0x80, TC_INS_CREATE_EF, 0x00, 0x00, 0x0E, 0x00, &La, TC_NOTCASE4_INS, data,sizeof(data), TC_MAX_APDU_WAIT);

		if(SW12 == 0x9000)
		{
			*pwEFId = efId;
			return 0;
		}

		if (SW12 == 0x6381)
			return 1;

		if (SW12 == 0x6982)
			return 2;

		return 3;
	}
	else
		return 1;

}

// Returns one for success, zero for fail
int tcWriteEF(WORD wEFId, BYTE *pData, WORD wLen)
{
	WORD fileSize;
	int status = 0;
	WORD offset = 0;
	BYTE hi,lo;
	WORD numBlocks;
	WORD remain;
	WORD i;
	WORD SW12;
	WORD La;

	// Select EF
	if(tcSelectEF(wEFId,&fileSize))
	{
		// Check the data will fit in the file
		if(wLen <= fileSize)
		{
			// Write data in blocks to the file
			numBlocks = wLen / 255;
			remain = wLen % 255;

			SW12 = 0x9000;
			for(i = 0; i < numBlocks && SW12 == 0x9000; i++)
			{
				hi = offset / 256;
				lo = offset % 256;
				SW12 = multosSendAPDU(0x80, TC_INS_UPD_BINARY, hi, lo, 0xFF, 0x00, &La, TC_NOTCASE4_INS, pData + offset,wLen, TC_MAX_APDU_WAIT);
				offset += 255;
			}
			if(SW12 == 0x9000 && remain > 0)
			{
				hi = offset / 256;
				lo = offset % 256;
				SW12 = multosSendAPDU(0x80, TC_INS_UPD_BINARY, hi, lo, remain, 0x00, &La, TC_NOTCASE4_INS, pData + offset,wLen, TC_MAX_APDU_WAIT);
			}

			status = (SW12 == 0x9000);
		}
	}

	return status;
}

WORD tcReadCurrentEF(WORD wOffset, WORD wNumBytes, BYTE *pBuffer)
{
	BYTE hi,lo;
	WORD SW12;
	WORD La;
	WORD numBlocks;
	WORD remain;
	WORD i;
	WORD currOffset;
	WORD nRead;
	WORD blockSize = 240;

	currOffset = wOffset;
	numBlocks = wNumBytes / blockSize;
	remain = wNumBytes % blockSize;

	memset(pBuffer,0xCC,wNumBytes);
	SW12 = 0x9000;
	nRead = 0;
	for(i = 0; i < numBlocks && SW12 == 0x9000; i++)
	{
		hi = currOffset / 256;
		lo = currOffset % 256;
		SW12 = multosSendAPDU(0x80, TC_INS_READ_BINARY, hi, lo, 0x00, blockSize, &La, TC_NOTCASE4_INS, pBuffer + currOffset,blockSize, TC_MAX_APDU_WAIT);
		currOffset += La;
		nRead += La;
	}
	if(SW12 == 0x9000 && remain > 0)
	{
		hi = currOffset / 256;
		lo = currOffset % 256;
		SW12 = multosSendAPDU(0x80, TC_INS_READ_BINARY, hi, lo, 0x00, remain, &La, TC_NOTCASE4_INS, pBuffer + currOffset,remain, TC_MAX_APDU_WAIT);
		nRead += La;
	}

	if (SW12 == 0x9000)
		return nRead;
	return 0;
}

WORD tcReadRsaModulus(WORD wEFId, BYTE *pBuffer, WORD wBuffSize)
{
	WORD La;
	WORD SW12;
	BYTE hi,lo;

	hi = wEFId / 256;
	lo = wEFId % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_READ_MODULUS, hi, lo, 0x00, 0x00, &La, TC_NOTCASE4_INS, pBuffer,wBuffSize, TC_MAX_APDU_WAIT);

	if(SW12 == 0x9000)
		return La;
	else
		return 0;
}

int tcMseRestore(BYTE bSecurityEnvironmentNumber)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_MANAGE_SE, TC_P1_RESTORE_SE, bSecurityEnvironmentNumber, 0x00, 0x00, &La, TC_NOTCASE4_INS, NULL,0, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcMseSetKeyFile(WORD wEFId, BYTE bTemplateID)
{
	WORD La;
	WORD SW12;
	BYTE data[4];

	// Key ID
	data[0] = 0x81; // Tag
	data[1] = 0x02; // Length
	data[2] = wEFId / 256; // Value
	data[3] = wEFId % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_MANAGE_SE, TC_P1_SET_SE, bTemplateID, 4, 0x00, &La, TC_NOTCASE4_INS, (BYTE*)data, sizeof(data), TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcMseSetAlgo(BYTE bAlgo, BYTE bTemplateID)
{
	WORD La;
	WORD SW12;
	BYTE data[3];

	data[0] = 0x80;
	data[1] = 0x01;
	data[2] = bAlgo;

	SW12 = multosSendAPDU(0x80, TC_INS_MANAGE_SE, TC_P1_SET_SE, bTemplateID, 3, 0x00, &La, TC_NOTCASE4_INS, (BYTE*)data, sizeof(data), TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}


int tcMseSetCipherSuite(WORD wCipherSuite)
{
	WORD La;
	WORD SW12;
	BYTE data[4];

	data[0] = 0x85;
	data[1] = 0x02;
	data[2] = wCipherSuite / 256;
	data[3] = wCipherSuite % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_MANAGE_SE, TC_P1_SET_SE, TC_TEMPLATE_TLS, 4, 0x00, &La, TC_NOTCASE4_INS, (BYTE*)data, sizeof(data), TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}


int tcMseSetTlsKeyLengths(BYTE bKeyLen, BYTE bMacLen, BYTE bRecordIvLen)
{
	WORD La;
	WORD SW12;
	BYTE data[5];

	data[0] = 0x86;
	data[1] = 0x03;
	data[2] = bKeyLen;
	data[3] = bMacLen;
	data[4] = bRecordIvLen;

	SW12 = multosSendAPDU(0x80, TC_INS_MANAGE_SE, TC_P1_SET_SE, TC_TEMPLATE_TLS, 5, 0x00, &La, TC_NOTCASE4_INS, (BYTE*)data, sizeof(data), TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcPreloadPublicKey(WORD wLen)
{
	WORD La;
	WORD SW12;
	BYTE data[4];

	data[0] = wLen / 256;
	data[1] = wLen % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_PRELOAD_KEY, 0x00, 0x00, 2, 0x00, &La, TC_CASE4_INS, data, sizeof(data), TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}


// Returns:
// 0: OK
// 1: CipherText length not valid in some way.
// 2: PlainText buffer too small
// 3: Operation failed
int tcDecrypt(BYTE *pCipherText, WORD wCipherLen, BYTE *pIv, BYTE bIvLen, BYTE *pPlainText, WORD *pwPlainLen)
{
	WORD La;
	WORD SW12;
	BYTE tempBuff[TC_DECRYPT_BUFF_SIZE];

	if( wCipherLen + bIvLen > TC_DECRYPT_BUFF_SIZE )
		return 1;

	if(bIvLen)
		memcpy(tempBuff,pIv,bIvLen);
	memcpy(tempBuff+bIvLen,pCipherText,wCipherLen);

	SW12 = multosSendAPDU(0x80,TC_INS_PSO,TC_PARAM_PLAIN,TC_PARAM_CRYPTOGRAM,wCipherLen + bIvLen,0,&La,TC_CASE4_INS,tempBuff,sizeof(tempBuff), TC_MAX_APDU_WAIT * 5);

	if(SW12 != 0x9000)
		return 3;

	// Copy back the result if a buffer was supplied and is big enough
	if(pPlainText)
	{
		if(*pwPlainLen >= La)
			memcpy(pPlainText,tempBuff,La);
		else
			return 2;
	}

	*pwPlainLen = La;
	return 0;
}

// Returns:
// 0: OK
// 1: CipherText length not valid in some way.
// 2: PlainText buffer too small
// 3: Operation failed
int tcDecryptGcm(BYTE *pCipherText, WORD wCipherLen, BYTE *pIv, BYTE bIvLen, BYTE *pAdd, BYTE bAddLen, BYTE *pPlainText, WORD *pwPlainLen)
{
	WORD La;
	WORD SW12;
	BYTE tempBuff[TC_DECRYPT_BUFF_SIZE];
	BYTE *p = tempBuff;

	// Validate input lengths. Must not be too big in total or have too little cipher text (minimum is the tag which is 16 bytes)
	if( (wCipherLen + bIvLen + bAddLen + 2u > (unsigned)sizeof(tempBuff)) || (wCipherLen < 16u))
		return 1;

	// Build input data into a buffer
	*p++ = bIvLen;
	if(bIvLen)
	{
		memcpy(p,pIv,bIvLen);
		p += bIvLen;
	}
	*p++ = bAddLen;
	if(bAddLen)
	{
		memcpy(p,pAdd,bAddLen);
		p += bAddLen;
	}
	// The last 16 bytes of CipherText are the Tag value, needed now.
	memcpy(p,pCipherText+wCipherLen-16,16);
	p += 16;
	// Finally the cipher text itself
	memcpy(p,pCipherText,wCipherLen-16);

	SW12 = multosSendAPDU(0x80,TC_INS_PSO,TC_PARAM_PLAIN,TC_PARAM_CRYPTOGRAM,wCipherLen+bIvLen+bAddLen+2,0,&La,TC_CASE4_INS,tempBuff,sizeof(tempBuff), TC_MAX_APDU_WAIT * 5);

	if(SW12 != 0x9000)
		return 3;

	// Copy back the result if a buffer was supplied and is big enough
	if(pPlainText)
	{
		if(*pwPlainLen >= La)
			memcpy(pPlainText,tempBuff,La);
		else
			return 2;
	}

	*pwPlainLen = La;
	return 0;
}

// Returns:
// 0: OK
// 1: PlainText length not valid in some way.
// 2: CipherText buffer too small
// 3: Operation failed
int tcEncrypt(BYTE *pPlainText, WORD wPlainLen, BYTE *pIv, BYTE bIvLen, BYTE *pCipherText, WORD *pwCipherLen)
{
	WORD La;
	WORD SW12;
	BYTE tempBuff[TC_DECRYPT_BUFF_SIZE];

	if( wPlainLen + bIvLen > TC_DECRYPT_BUFF_SIZE )
		return 1;

	if(bIvLen)
		memcpy(tempBuff,pIv,bIvLen);
	memcpy(tempBuff+bIvLen,pPlainText,wPlainLen);

	SW12 = multosSendAPDU(0x80,TC_INS_PSO,TC_PARAM_CRYPTOGRAM,TC_PARAM_PLAIN, bIvLen + wPlainLen,0,&La,TC_CASE4_INS,tempBuff,sizeof(tempBuff), TC_MAX_APDU_WAIT*5);
	if(SW12 != 0x9000)
		return 3;

	// Copy back the result if a buffer was supplied and is big enough
	if(pCipherText)
	{
		if(*pwCipherLen >= La)
			memcpy(pCipherText,tempBuff,La);
		else
			return 2;
	}
	*pwCipherLen = La;
	return 0;
}

// Returns:
// 0: OK
// 1: PlainText length not valid in some way.
// 2: CipherText buffer too small
// 3: Operation failed
int tcEncryptGcm(BYTE *pPlainText, WORD wPlainLen, BYTE *pIv, BYTE bIvLen, BYTE *pAdd, BYTE bAddLen, BYTE *pCipherText, WORD *pwCipherLen)
{
	WORD La;
	WORD SW12;
	BYTE tempBuff[TC_DECRYPT_BUFF_SIZE];
	BYTE *p = tempBuff;

	// Validate input lengths
	if( (wPlainLen + bIvLen + bAddLen + 2u > (unsigned)sizeof(tempBuff)) || (bIvLen + bAddLen < (unsigned)AES_BLOCK_LEN) )
		return 1;

	// Build input data into a buffer
	*p++ = bIvLen;
	if(bIvLen)
	{
		memcpy(p,pIv,bIvLen);
		p += bIvLen;
	}
	*p++ = bAddLen;
	if(bAddLen)
	{
		memcpy(p,pAdd,bAddLen);
		p += bAddLen;
	}
	memcpy(p,pPlainText,wPlainLen);

	SW12 = multosSendAPDU(0x80,TC_INS_PSO,TC_PARAM_CRYPTOGRAM,TC_PARAM_PLAIN,bIvLen+wPlainLen+bAddLen+2,0,&La,TC_CASE4_INS,tempBuff,sizeof(tempBuff), TC_MAX_APDU_WAIT*5);

	if(SW12 != 0x9000)
		return 3;

	// Copy back the result if a buffer was supplied and is big enough
	if(pCipherText)
	{
		if(*pwCipherLen >= La)
			memcpy(pCipherText,tempBuff,La);
		else
			return 2;
	}

	*pwCipherLen = La;
	return 0;
}

// Returns:
// 0: OK
// 1: Data length not valid in some way.
// 2: Signature buffer too small
// 3: Operation failed
int tcSign(BYTE *pData, WORD wDataLen, BYTE *pSignature, WORD *pwSigLen)
{
	WORD La;
	WORD SW12 = 0x9000;
	BYTE tempBuff[TC_DECRYPT_BUFF_SIZE];

	if( wDataLen > TC_DECRYPT_BUFF_SIZE )
		return 1;

	memcpy(tempBuff,pData,wDataLen);

	if(pSignature)
		SW12 = multosSendAPDU(0x80,TC_INS_PSO,TC_PARAM_DIGSIG,TC_PARAM_DIGSIG_INP,wDataLen,0,&La,TC_CASE4_INS,tempBuff,TC_DECRYPT_BUFF_SIZE, TC_MAX_APDU_WAIT * 5);

	if(SW12 != 0x9000)
	{
		//printf("...APDU SW12=%04x\n",SW12);
		return 3;
	}

	// Copy back the result if a buffer was supplied and is big enough
	if(pSignature)
	{
		if(*pwSigLen >= La)
			memcpy(pSignature,tempBuff,La);
		else
			return 2;
	}

	*pwSigLen = La;
	return 0;
}

// Returns:
// 0: OK
// 1: Key length not valid
// 2: Operation failed
int tcGenerateRsaKey(WORD wEFId, WORD wModulusLenBits)
{
	WORD La;
	WORD SW12;
	BYTE data[3];

	data[0] = wEFId / 256;
	data[1] = wEFId % 256;
	switch(wModulusLenBits)
	{
		case(512): data[2] = 0x40; break;
		case(768): data[2] = 0x60; break;
		case(1024): data[2] = 0x80; break;
		case(2048): data[2] = 0x00; break;
		default: return 1; // Invalid length
	}

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_RSA, 0x00, 3, 0x00, &La, TC_CASE4_INS, (BYTE*)data, sizeof(data), 60000);

	if(SW12 != 0x9000)
		return 2;

	// All OK
	return 0;
}

int tcGenerateEcKey(WORD wEFId, BYTE bCurveId, BYTE bEcdhOnly, BYTE *pOut)
{
	WORD La;
	WORD SW12;
	BYTE data[140]; // Big enough to hold the longest public key that could be returned

	data[0] = wEFId / 256;
	data[1] = wEFId % 256;
	data[2] = bCurveId;

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_ECC, bEcdhOnly, 3, 0x00, &La, TC_CASE4_INS, (BYTE*)data, sizeof(data), 30000);

	if(SW12 != 0x9000)
		return 0;

	memcpy(pOut,data,La);
	return 1;
}

int tcAskRandom(BYTE bNumBytes, BYTE *pData)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_RANDOM, 0x00, 0x00, 0x00, bNumBytes, &La, TC_NOTCASE4_INS, pData, bNumBytes, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;

}

int tcShaInit(BYTE bHashLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_SHA, bHashLen, TC_P2_SHA_INIT, 0x00, 0x00, &La, TC_NOTCASE4_INS, NULL, 0, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcShaUpdate(BYTE *abData, WORD wLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_SHA, 0x00, TC_P2_SHA_UPDATE, wLen, 0x00, &La, TC_NOTCASE4_INS, abData, wLen, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

// abData is assumed to point to a buffer that is big enough to hold the result.
WORD tcShaFinal(BYTE *abData)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_SHA, 0x00, TC_P2_SHA_FINAL, 0x00, 0x00, &La, TC_NOTCASE4_INS, abData, 64, TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000)
		return La;
	else
		return 0;
}

WORD tcSha(BYTE bHashLen, BYTE *abData, WORD wLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_SHA, bHashLen, TC_P2_SHA_ONESHOT, wLen, 0x00, &La, TC_CASE4_INS, abData, 32, TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000)
		return La;
	else
		return 0;
}

int tcHandshakeShaInit(BYTE bHashLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_HANDSHAKE_SHA, bHashLen, TC_P2_SHA_INIT, 0x00, 0x00, &La, TC_NOTCASE4_INS, NULL, 0, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcHandshakeShaUpdate(BYTE *abData, WORD wLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_HANDSHAKE_SHA, 0x00, TC_P2_SHA_UPDATE, wLen, 0x00, &La, TC_NOTCASE4_INS, abData, wLen, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

WORD tcHandshakeShaFinal(BYTE *abData)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_HANDSHAKE_SHA, 0x00, TC_P2_SHA_FINAL, 0x00, 0x00, &La, TC_NOTCASE4_INS, abData, 32, TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000)
		return La;
	else
		return 0;
}

int tcDeleteFile(WORD EFId)
{
	WORD La;
	WORD SW12;
	BYTE abData[256];

	abData[0] = EFId / 256;
	abData[1] = EFId % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_DELETE_EF, 0x00, 0x00, 2, 0x00, &La, TC_NOTCASE4_INS, abData, 256, TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

int tcGeneratePreMasterSecret(BYTE bTlsMajVer, BYTE bTlsMinVer, CK_OBJECT_HANDLE *EFId)
{
	WORD La;
	WORD SW12;
	BYTE abData[2];

	abData[0] = bTlsMajVer;
	abData[1] = bTlsMinVer;

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_PMS, TC_P1_PMS_STD, 2, 0x00, &La, TC_CASE4_INS, abData, sizeof(abData), TC_MAX_APDU_WAIT);
	if(La == 2)
	{
		*EFId = abData[0]*256 + abData[1];
	}

	return SW12 == 0x9000;
}

int tcGeneratePreMasterSecretAlgo(BYTE *pOtherPublicKey, WORD wOtherPublicKeyLen, CK_OBJECT_HANDLE *EFId)
{
	WORD La;
	WORD SW12;
	BYTE abData[TC_DECRYPT_BUFF_SIZE];

	if(wOtherPublicKeyLen > sizeof(abData))
		return 0;

	memcpy(abData,pOtherPublicKey,wOtherPublicKeyLen);

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_PMS, TC_P1_PMS_USE_ALGO, wOtherPublicKeyLen, 0x00, &La, TC_CASE4_INS, abData, sizeof(abData), TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000 && La == 2)
	{
		*EFId = abData[0]*256 + abData[1];
		return 1;
	}
	return 0;
}

int tcGenerateMasterSecret(CK_OBJECT_HANDLE wPmsEFId,BYTE bExtended, BYTE *pData, WORD wDataLen, CK_OBJECT_HANDLE *wMsEFId, BYTE *bTlsMajVer, BYTE *bTlsMinVer)
{
	WORD La;
	WORD SW12;
	BYTE abData[66];

	abData[0] = wPmsEFId / 256;
	abData[1] = wPmsEFId % 256;
	memcpy(abData+2,pData,wDataLen);

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_MS, bExtended, wDataLen+2, 0x00, &La, TC_CASE4_INS, abData, wDataLen+2, TC_MAX_APDU_WAIT);
	if(La == 4)
	{
		*wMsEFId = abData[2]*256 + abData[3];
		*bTlsMajVer = abData[0];
		*bTlsMinVer = abData[1];
	}

	return SW12 == 0x9000;
}

int tcGenerateSessionKeys(BYTE *pServerThenClientRandom,
		CK_OBJECT_HANDLE *hClientWriteMac, CK_OBJECT_HANDLE *hServerWriteMac, CK_OBJECT_HANDLE *hClientWrite, CK_OBJECT_HANDLE *hServerWrite,
		BYTE *pClientWriteIv, BYTE *pServerWriteIv)
{
	WORD La;
	WORD SW12;
	BYTE abData[64];

	memcpy(abData,pServerThenClientRandom,64);

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_TLS_KEYSET, 0x00, 64, 0x00, &La, TC_CASE4_INS, abData, 64, TC_MAX_APDU_WAIT*5);
	if(SW12 == 0x9000 && La == 40)
	{
		*hClientWriteMac = abData[0]*256 + abData[1];
		*hServerWriteMac = abData[2]*256 + abData[3];
		*hClientWrite = abData[4]*256 + abData[5];
		*hServerWrite = abData[6]*256 + abData[7];
		memcpy(pClientWriteIv,abData+8,16);
		memcpy(pServerWriteIv,abData+24,16);
		return 1;
	}
	return 0;
}

int tcWrapKey(CK_OBJECT_HANDLE hKeyToWrap, BYTE *pOutput, CK_ULONG *pLength)
{
	WORD La;
	WORD SW12 = 0;
	BYTE abData[512];

	abData[0] = hKeyToWrap / 256;
	abData[1] = hKeyToWrap % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_PSO, TC_PARAM_WRAP, TC_PARAM_CRYPTOGRAM, 2, 0x00, &La, TC_CASE4_INS, abData, 512, TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000)
	{
		if(La <= *pLength)
		{
			memcpy(pOutput,abData,La);
			*pLength = La;
		}
		else
		{
			memcpy(pOutput,abData,*pLength);
		}
		return 1;
	}
	return 0;
}

// For secret key files only
int tcReadSecretKeyAttrs(CK_OBJECT_HANDLE hKey, TC_SECRET_KEY_ATTRS *pAttrs)
{
	WORD La;
	WORD SW12;
	BYTE P1,P2;

	P1 = hKey / 256;
	P2 = hKey % 256;

	SW12 = multosSendAPDU(0x80, TC_INS_READ_ATTRS, P1, P2, 0, 35,&La,TC_NOTCASE4_INS,(BYTE*)pAttrs,sizeof(TC_SECRET_KEY_ATTRS),TC_MAX_APDU_WAIT);

	return SW12 == 0x9000;
}

// RSA verify, effectively an in-place decryption
// Returns:
// 0 : OK
// 1: Bad signature length
// 3: Something else went wrong
int tcVerify(BYTE *pSig, WORD wSigLen)
{
	WORD La;
	WORD SW12;

	SW12 = multosSendAPDU(0x80, TC_INS_PSO, TC_PARAM_VERFIY, TC_PARAM_DIGSIG_INP, wSigLen, 0, &La, TC_CASE4_INS,pSig,wSigLen,TC_MAX_APDU_WAIT);

	if(SW12 == 0x6700)
		return 1;
	else if (SW12 == 0x6A80)
		return 2;
	else if (SW12 != 0x9000)
		return 3;
	else
		return 0;
}

int tcVerifyECDSA(BYTE *pHash, WORD wHashLen, BYTE *pSignature, WORD wSigLen)
{
	WORD La;
	WORD SW12;
	BYTE *p;

	p = (BYTE*)malloc(wSigLen + wHashLen);
	if (p == 0)
		return 0;

	memcpy(p,pSignature,wSigLen);
	memcpy(p+wSigLen,pHash,wHashLen);

	SW12 = multosSendAPDU(0x80, TC_INS_PSO, TC_PARAM_VERFIY, TC_PARAM_DIGSIG_INP, wSigLen + wHashLen, 0, &La, TC_CASE4_INS,p,wSigLen + wHashLen,TC_MAX_APDU_WAIT);

	if(SW12 == 0x6700)
		return 1;
	else if (SW12 == 0x6A80)
		return 2;
	else if (SW12 != 0x9000)
		return 3;
	else
		return 0;
}

int tcGenerateAesKey(BYTE *pLabel, BYTE bLen, WORD wFlags, CK_OBJECT_HANDLE *pEFId)
{
	WORD La;
	WORD SW12;
	BYTE abData[TC_SECRET_KEY_LABEL_LEN+1+sizeof(wFlags)+sizeof(bLen)];

	memcpy(abData,pLabel,TC_SECRET_KEY_LABEL_LEN+1);
	abData[TC_SECRET_KEY_LABEL_LEN+1] = bLen;
	abData[TC_SECRET_KEY_LABEL_LEN+2] = wFlags % 256;
	abData[TC_SECRET_KEY_LABEL_LEN+3] = wFlags / 256;

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_AES, 0x00, sizeof(abData), 0x00, &La, TC_CASE4_INS, abData, sizeof(abData), TC_MAX_APDU_WAIT);
	if(La == 2)
		*pEFId = abData[0]*256 + abData[1];
	else
		*pEFId = 0;

	return SW12 == 0x9000;
}

int tcImportAesKey(BYTE *pLabel, BYTE bLen, WORD wFlags, BYTE *pValue, CK_OBJECT_HANDLE *pEFId)
{
	WORD La;
	WORD SW12;
	BYTE abData[TC_SECRET_KEY_LABEL_LEN+1+sizeof(wFlags)+sizeof(bLen)+32];
	WORD l = 0;

	memcpy(abData,pLabel,TC_SECRET_KEY_LABEL_LEN+1);
	l += TC_SECRET_KEY_LABEL_LEN+1;
	abData[l++] = bLen;
	abData[l++] = wFlags % 256;
	abData[l++] = wFlags / 256;
	memcpy(abData+l,pValue,bLen);
	l += bLen;

	SW12 = multosSendAPDU(0x80, TC_INS_GEN_KEY, TC_KEYTYPE_AES, 0x00, l, 0x00, &La, TC_CASE4_INS, abData, sizeof(abData), TC_MAX_APDU_WAIT);
	if(La == 2)
		*pEFId = abData[0]*256 + abData[1];
	else
		*pEFId = 0;

	return SW12 == 0x9000;
}


int tcUnwrapKey(WORD wFlags, BYTE *pAesLabel, BYTE *pCheckValue, BYTE bAesKeyLen,BYTE *pWrappedKey,CK_ULONG ulWrappedKeyLen, CK_OBJECT_HANDLE_PTR phKey)
{
	WORD La;
	WORD SW12;
	BYTE abData[128];
	WORD Lc = 0;

	// Assemble the data into order
	abData[Lc++] = wFlags % 256;
	abData[Lc++] = wFlags / 256;
	memcpy(abData+Lc,pAesLabel,TC_SECRET_KEY_LABEL_LEN+1);
	Lc = Lc + TC_SECRET_KEY_LABEL_LEN+1;
	memcpy(abData+Lc,pCheckValue,3);
	Lc += 3;
	abData[Lc++] = bAesKeyLen;
	memcpy(abData+Lc,pWrappedKey,ulWrappedKeyLen);
	Lc += ulWrappedKeyLen;

	SW12 = multosSendAPDU(0x80, TC_INS_PSO, TC_PARAM_CRYPTOGRAM, TC_PARAM_WRAP, Lc, 0x02, &La, TC_CASE4_INS, abData, sizeof(abData), TC_MAX_APDU_WAIT);
	if(SW12 == 0x9000 && La == 2)
	{
		*phKey = (abData[0] * 256) + abData[1];
		return 1;
	}
	return 0;
}

int tcEraseTLSKeys()
{
	WORD La;
	WORD SW12;
	BYTE abDummy[4];

	SW12 = multosSendAPDU(0x80, TC_INS_ERASE_TLS, 0, 0, 0, 0, &La, TC_NOTCASE4_INS,abDummy,sizeof(abDummy),TC_MAX_APDU_WAIT);

	return(SW12 == 0x9000);
}

int tcLoadUntrustedPublicKey(BYTE *pModulus, WORD wModLen, BYTE *pExponent, BYTE bExpLen)
{
	WORD La;
	WORD SW12;
	BYTE *pBuff;
	
	pBuff = (BYTE *)malloc(6 + wModLen);
	if(pBuff == NULL)
		return 0;

	memset(pBuff,0,6+wModLen);
	pBuff[0] = bExpLen;
	pBuff[1] = wModLen / 256;
	pBuff[2] = wModLen % 256;
	memcpy(pBuff+3,pExponent,bExpLen <= 3 ? bExpLen : 3);
	memcpy(pBuff+6,pModulus,wModLen);

	SW12 = multosSendAPDU(0x80, TC_INS_UNTRUSTED_KEY, TC_P1_RSA_PUB_KEY, 0, 6 + wModLen, 0, &La, TC_NOTCASE4_INS,pBuff,6 + wModLen,TC_MAX_APDU_WAIT);
	free(pBuff);
	
	return(SW12 == 0x9000);
}

int tcLoadUntrustedPublicEccKey(BYTE bCurveId,BYTE *pPubKey, WORD wPubKeyLen)
{
	WORD La;
	WORD SW12;
	BYTE *pBuff;

	pBuff = (BYTE *)malloc(1 + wPubKeyLen);
	if(pBuff == NULL)
		return 0;

	pBuff[0] = bCurveId;
	memcpy(pBuff+1,pPubKey,wPubKeyLen);

	SW12 = multosSendAPDU(0x80, TC_INS_UNTRUSTED_KEY, TC_P1_ECC_PUB_KEY, 0, 1 + wPubKeyLen, 0, &La, TC_NOTCASE4_INS,pBuff,1 + wPubKeyLen,TC_MAX_APDU_WAIT);
	free(pBuff);

	return(SW12 == 0x9000);
}

int tcGetVersion(BYTE *pbMajor, BYTE *pbMinor)
{
	WORD La;
	WORD SW12;
	BYTE abData[4];

	SW12 = multosSendAPDU(0x80, TC_INS_VERSION, 0, 0, 0, 2, &La, TC_NOTCASE4_INS,abData,sizeof(abData),TC_MAX_APDU_WAIT);
	if(La == 2)
	{
		*pbMajor = abData[0];
		*pbMinor = abData[1];
	}

	return(SW12 == 0x9000);
}
