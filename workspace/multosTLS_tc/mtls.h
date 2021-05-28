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

#ifndef mtls_h_
#define mtls_h_

#ifdef __cplusplus
extern "C" {
#endif

// Control functions
extern int mtlsInit(unsigned short wCipherSuite);
extern int mtlsFinish(void);
extern void mtlsVersion(unsigned char *major, unsigned char *minor);

// Message encryption and MACing
extern unsigned short mtlsEncryptDecrypt(unsigned char *bSeqNum, unsigned char bContentType, unsigned short wProtocolVersion, unsigned short wDataLen, unsigned char *pData, int sending, unsigned char *pIV) ;
extern int mtlsEncryptDecryptOnly(unsigned char *pData, unsigned long dwDataLen, int sending, unsigned char *pIV);
extern unsigned short mtlsHMAC(unsigned char *pIn, unsigned short wInLen,  unsigned char client, unsigned char *pOut,  unsigned short wOutSize);
extern int mtlsGenerateRandom(unsigned short len, unsigned char *pOut);
extern int mtlsSetAdditionalData(unsigned char *pData, unsigned short wDataLen);

// Handshake functions
extern int mtlsGenerateClientRandom(unsigned long dwServerTime, unsigned char bUseTime, unsigned char *pOut,  unsigned short wOutSize);
extern unsigned short mtlsGeneratePreMasterSecret(unsigned char bMajor, unsigned char bMinor, unsigned char *pPubKey, unsigned short wPubKeyLen, unsigned char *pExponent, unsigned char bExpLen, unsigned char *pOut,  unsigned short wOutSize);
extern int mtlsGenerateMasterSecret(unsigned char *pServerRandom);
extern int mtlsGenerateMasterSecretExtended(unsigned char *abHandshakeHash, unsigned short wHashLen, unsigned char *pServerRandom);
extern int mtlsGenerateKeys(unsigned char **pClientIvPtr, unsigned char **pServerIvPtr);
extern unsigned short mtlsGenerateFinalFinishMAC(char *sLabel, unsigned char *abHandshakeHash, unsigned short wHashLen, unsigned char *pOut,  unsigned short wOutSize);
extern int mtlsHandshakeHashInit(void);
extern int mtlsHandshakeHashUpdate(unsigned char *pData, unsigned short wLen);
extern unsigned short mtlsHandshakeHashCurrent(unsigned char *pOut);

// RSA functions
extern int mtlsGenerateRsaKeyPair(char *sFileName, char *sCountryName, char *sStateOrProvinceName, char *sLocalityName, char *sOrgName, char *sOrgUnit, char *sCommonName, char *sEmailAddress);
extern int mtlsRsaVerifySignature(unsigned char *pModulus, unsigned short wModLen, unsigned char *pExponent, unsigned char bExpLen, unsigned char *pData, unsigned short wDataLen, unsigned char *pSignature);
extern int mtlsRsaSignPKCS1_type1(unsigned char *pData, unsigned short wDataLen, unsigned char bDoHash, unsigned char **pOutPtr);
extern int mtlsRsaSignPKCS1_PSS(unsigned char *pData, unsigned short wDataLen, unsigned char bDoHash, unsigned char **pOutPtr);


// ECC functions
extern int mtlsECDSASign(unsigned char *pHash, unsigned short wHashLen, unsigned char *pSignature);
extern int mtlsECDSAVerify(unsigned char *pPubKey, unsigned short wPubKeyLen, unsigned char bNamedCurve, unsigned char *pData, unsigned short wDataLen, unsigned char *pSignature);
extern int mtlsGenerateEphemeralECKey(unsigned char bNamedCurve,unsigned char *pPubKey);

#ifdef __cplusplus
}
#endif

#endif // mtls_h_
