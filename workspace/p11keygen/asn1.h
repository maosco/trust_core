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


#ifndef ASN1_H_
#define ASN1_H_

extern unsigned short getRsaSignMethodLength();
extern unsigned short getEcSignMethodLength();

extern unsigned short makeCertInfoSequence(
		unsigned char *abInfoSeq,
		size_t buffSize,
		char *sCountryName,
		char *sStateOrProvinceName,
		char *sLocalityName,
		char *sOrgName,
		char *sOrgUnit,
		char *sCommonName,
		char *sEmailAddress
		);

extern unsigned short makeSigDataSequence(
		unsigned char *abSigData, // Output buffer
		size_t buffSize, // Size of output buffer
		unsigned char *abInfoSeq,
		unsigned short wInfoSeqLen,
		unsigned char *pPubKeySeq,
		unsigned short wPubKeySeqLen);

extern unsigned short makeEccCsrSequence(
		unsigned char *abFullSeq, // Output buffer
		size_t buffSize,
		unsigned short wSeqLen, // pre-calculated length of CSR sequence
		unsigned char *abSigData,
		unsigned short wSigDataLen,
		unsigned char *abSignature,
		unsigned char bEcPrimeLen);

extern unsigned short makeRsaCsrSequence(
		unsigned char *abFullSeq, // Output buffer
		size_t buffSize,
		unsigned short wSeqLen, // pre-calculated length of CSR sequence
		unsigned char *abSigData,
		unsigned short wSigDataLen,
		unsigned char *abSignature,
		unsigned short wSigLen);

#endif /* ASN1_H_ */
