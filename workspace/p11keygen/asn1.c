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

#include <stdio.h>
#include <string.h>
#include "asn1.h"

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

static unsigned char ASN1_SEQ_RSASIGN_METHOD[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00};
static unsigned char ASN1_SEQ_ECSIGN256_METHOD[] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
static unsigned char ASN1_SEQ_ECSIGN384_METHOD[] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03};
static unsigned char ASN1_SEQ_ECSIGN512_METHOD[] = {0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04};


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

unsigned short getRsaSignMethodLength()
{
	return sizeof(ASN1_SEQ_RSASIGN_METHOD);
}

unsigned short getEcSignMethodLength()
{
	return sizeof(ASN1_SEQ_ECSIGN256_METHOD);
}

// Make the Certificate Information Sequence from the input parameters
unsigned short makeCertInfoSequence(
		unsigned char *abInfoSeq, // Output buffer
		size_t buffSize, // Size of output buffer
		char *sCountryName,
		char *sStateOrProvinceName,
		char *sLocalityName,
		char *sOrgName,
		char *sOrgUnit,
		char *sCommonName,
		char *sEmailAddress
		)
{
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
	unsigned short wInfoSeqLen, w;

	bCNLen = asn1MakeSet(OID_CN,sizeof(OID_CN),ASN1_PrintableString,sCountryName,abCNSet);
	bSTLen = asn1MakeSet(OID_ST,sizeof(OID_ST),ASN1_UTF8String,sStateOrProvinceName,abSTSet);
	bLOLen = asn1MakeSet(OID_LO,sizeof(OID_LO),ASN1_UTF8String,sLocalityName,abLOSet);
	bORLen = asn1MakeSet(OID_OR,sizeof(OID_OR),ASN1_UTF8String,sOrgName,abORSet);
	bOULen = asn1MakeSet(OID_OU,sizeof(OID_OU),ASN1_UTF8String,sOrgUnit,abOUSet);
	bCMLen = asn1MakeSet(OID_CM,sizeof(OID_CM),ASN1_UTF8String,sCommonName,abCMSet);
	bEMLen = asn1MakeSet(OID_EM,sizeof(OID_EM),ASN1_IA5String,sEmailAddress,abEMSet);
	wInfoSeqLen = bCNLen + bSTLen + bLOLen + bORLen + bOULen + bCMLen + bEMLen;
	if(wInfoSeqLen+4 > buffSize)
	{
		fprintf(stderr,"ERROR: Certificate info sequence too long\n");
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

	return w;
}

unsigned short makeSigDataSequence(
		unsigned char *abSigData, // Output buffer
		size_t buffSize, // Size of output buffer
		unsigned char *abInfoSeq,
		unsigned short wInfoSeqLen,
		unsigned char *pPubKeySeq,
		unsigned short wPubKeySeqLen)
{
	unsigned short w, wSigDataLen;

	w = 0;
	wSigDataLen = wInfoSeqLen + wPubKeySeqLen + 3 + 2;
	if(wSigDataLen + 4 > buffSize)
	{
		fprintf(stderr,"ERROR: Signed sequence too long\n");
		return 0;
	}
	// Start of sequence with length byte(s)
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
	// ... the info sequence
	abSigData[w++] = ASN1_INT; //INTEGER 0 sequence element
	abSigData[w++] = 1;
	abSigData[w++] = 0;
	memcpy(abSigData+w,abInfoSeq,wInfoSeqLen); // SEQUENCE - 7 elements
	w += wInfoSeqLen;

	// ... the public key sequence
	memcpy(abSigData+w,pPubKeySeq,wPubKeySeqLen); // SEQUENCE - 2 elements

	w += wPubKeySeqLen;
	abSigData[w++] = ASN1_ZERO;
	abSigData[w++] = 0;

	return w;
}

unsigned short makeEccCsrSequence(
		unsigned char *abFullSeq, // Output buffer
		size_t buffSize,
		unsigned short wSeqLen, // pre-calculated length of CSR sequence
		unsigned char *abSigData,
		unsigned short wSigDataLen,
		unsigned char *abSignature,
		unsigned char bEcPrimeLen)
{
	unsigned short w;
	unsigned char bLen;

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

	if(bEcPrimeLen == 32)
	{
		memcpy(abFullSeq+w,ASN1_SEQ_ECSIGN256_METHOD,sizeof(ASN1_SEQ_ECSIGN256_METHOD));
		w += sizeof(ASN1_SEQ_ECSIGN256_METHOD);
	}
	else if(bEcPrimeLen == 48)
	{
		memcpy(abFullSeq+w,ASN1_SEQ_ECSIGN384_METHOD,sizeof(ASN1_SEQ_ECSIGN384_METHOD));
		w += sizeof(ASN1_SEQ_ECSIGN384_METHOD);
	}
	else
	{
		memcpy(abFullSeq+w,ASN1_SEQ_ECSIGN512_METHOD,sizeof(ASN1_SEQ_ECSIGN512_METHOD));
		w += sizeof(ASN1_SEQ_ECSIGN512_METHOD);
	}
	// BIT_STRING header
	abFullSeq[w++] = ASN1_BitString;
	bLen = (bEcPrimeLen*2) + 7;
	if(abSignature[0] > 0x7F)
		bLen++;
	if(abSignature[bEcPrimeLen] > 0x7F)
		bLen++;
	if(bLen > 0x7F)
	{
		abFullSeq[w++] = 0x81;
		bLen++; // The signature sequence header is also going to need an extra 0x81
	}
	abFullSeq[w++] = bLen;
	abFullSeq[w++] = 0;

	// Signature sequence header
	abFullSeq[w++] = ASN1_SEQ;
	bLen = (bEcPrimeLen*2) + 4;
	if(abSignature[0] > 0x7F)	// R needs padding so not to be negative
		bLen++;
	if(abSignature[bEcPrimeLen] > 0x7F) // S needs padding so not to be negative
		bLen++;
	if(bLen > 0x7F)
		abFullSeq[w++] = 0x81;
	abFullSeq[w++] = bLen;

	// R value
	abFullSeq[w++] = ASN1_INT;
	if(abSignature[0] > 0x7F)
	{
		abFullSeq[w++] = bEcPrimeLen + 1;
		abFullSeq[w++] = 0x00; // Extra byte to ensure not negative signed number
	}
	else
		abFullSeq[w++] = bEcPrimeLen;
	memcpy(abFullSeq + w, abSignature, bEcPrimeLen);
	w += bEcPrimeLen;

	// S value
	abFullSeq[w++] = ASN1_INT;
	if(abSignature[bEcPrimeLen] > 0x7F)
	{
		abFullSeq[w++] = bEcPrimeLen + 1;
		abFullSeq[w++] = 0x00; // Extra byte to ensure not negative signed number
	}
	else
		abFullSeq[w++] = bEcPrimeLen;
	memcpy(abFullSeq + w, abSignature + bEcPrimeLen, bEcPrimeLen);
	w += bEcPrimeLen;

	return w;
}

unsigned short makeRsaCsrSequence(
		unsigned char *abFullSeq, // Output buffer
		size_t buffSize,
		unsigned short wSeqLen, // pre-calculated length of CSR sequence
		unsigned char *abSigData,
		unsigned short wSigDataLen,
		unsigned char *abSignature,
		unsigned short wSigLen)
{
	unsigned short w;

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

	memcpy(abFullSeq+w,ASN1_SEQ_RSASIGN_METHOD,sizeof(ASN1_SEQ_RSASIGN_METHOD));
	w += sizeof(ASN1_SEQ_RSASIGN_METHOD);
	abFullSeq[w++] = ASN1_BitString;
	abFullSeq[w++] = 0x82;
	abFullSeq[w++] = (wSigLen+1) / 256;
	abFullSeq[w++] = (wSigLen+1) % 256;
	abFullSeq[w++] = 0x00; // Extra byte to ensure not negative signed number
	memcpy(abFullSeq + w, abSignature, wSigLen);
	w += wSigLen;

	return w;
}
