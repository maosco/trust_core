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

#ifndef TC_API_H_
#define TC_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <multosio.h>
#include "pkcs11.h"

#define TC_AID "A00000014454434F5245"

#define TC_MAX_APDU_WAIT	1000
#define AES_BLOCK_LEN		16
#define TC_PIN_SIZE		12
#define TC_NUM_SECRET_KEYS		10
#define TC_NUM_RSA_PRIV_KEYS	2
#define TC_NUM_EC_PRIV_KEYS		4
#define TC_NUM_FS_OBJS_PER_CLASS	10

#define TC_EF_PRIVKEY_1		0x6100	//RSA keys
#define TC_EF_PRIVKEY_2		0x6101

#define TC_EFTYPE_PRIVKEY		0x6100
#define TC_EFTYPE_PUBKEY		0x6000
#define TC_EFTYPE_CERT			0x5300
#define TC_EFTYPE_SECRET		0x6200
#define TC_EFTYPE_EC_PRIVKEY	0x6300

#define TC_PINREF_G		1
#define TC_PINREF_K		2
#define TC_PINREF_SO	3
#define TC_PINREF_NONE	0xFF

#define TC_ACCESS_NEVER		0x00000000
#define TC_ACCESS_ALWAYS	0x00000001
#define TC_ACCESS_USER		0x00000002
#define TC_ACCESS_KEYMAN	0x00000004
#define TC_ACCESS_SO		0x00000008

#define TC_ALGO_RSA					0x01	// Corresponds to CKM_RSA_PKCS
#define TC_ALGO_TLS					0x02	// Corresponds to CMK_TLS_KEY_AND_MAC_DERIVE
#define TC_ALGO_PSS_SHA1			0x03
#define TC_ALGO_PSS_SHA256			0x04
#define TC_ALGO_AES_CBC				0x05
#define TC_ALGO_SHA1_HMAC			0x06
#define TC_ALGO_SHA256_HMAC			0x07
#define TC_ALGO_TLS12_MAC_CLIENT	0x08
#define TC_ALGO_TLS12_MAC_SERVER	0x09
#define TC_ALGO_ECDSA				0x0A
#define TC_ALGO_AES_GCM				0x0B
#define TC_ALGO_ECDH1				0x0C

#define TC_TEMPLATE_DIGITAL_SIG		0xB6
#define TC_TEMPLATE_CONFIDENTIALITY	0xB8
#define TC_TEMPLATE_TLS				0xBA
#define TC_DECRYPT_BUFF_SIZE		3000	// Corresponds to CH_PUBLIC_SIZE_MAX in the Trust Core app

#define TC_CASE4_INS			0x01
#define TC_NOTCASE4_INS			0x00

#define TC_INS_VERIFY			0x20
#define TC_INS_MANAGE_SE		0x22
#define TC_INS_REF_DATA			0x24
#define TC_INS_PSO				0x2A
#define TC_INS_CHANGE			0x2C
#define TC_INS_READ_MODULUS		0x40
#define TC_INS_GEN_KEY			0x46
#define TC_INS_RANDOM			0x84
#define TC_INS_SHA				0x85
#define TC_INS_HANDSHAKE_SHA	0x86
#define TC_INS_VERSION			0x88
#define TC_INS_READ_BINARY		0xB0
#define TC_INS_READ_ATTRS		0xB1
#define TC_INS_UPD_BINARY		0xD6
#define TC_INS_CREATE_EF		0xE0
#define TC_INS_DELETE_EF		0xE4
#define TC_INS_PRELOAD_KEY		0xE5
#define TC_INS_UNTRUSTED_KEY	0xE6
#define TC_INS_ERASE_TLS		0xE7


#define TC_KEYTYPE_RSA			0x00
#define TC_KEYTYPE_ECC			0x01
#define TC_KEYTYPE_AES			0x02
#define TC_KEYTYPE_PMS			0x03
#define TC_KEYTYPE_MS			0x04
#define TC_TLS_KEYSET			0x05

#define TC_P1_SET_SE			0x41
#define TC_P1_RESTORE_SE		0xF3
#define TC_P1_PMS_STD			0x00
#define TC_P1_PMS_USE_ALGO		0x01
#define TC_P1_RSA_PUB_KEY		0x00
#define TC_P1_ECC_PUB_KEY		0x01

#define TC_P2_SHA_INIT			0x00
#define TC_P2_SHA_UPDATE		0x01
#define TC_P2_SHA_FINAL			0x02
#define TC_P2_SHA_ONESHOT		0x03

#define TC_PARAM_PLAIN			0x80
#define TC_PARAM_WRAP			0x81
#define TC_PARAM_CRYPTOGRAM		0x86
#define TC_PARAM_DIGSIG_INP		0x9A
#define TC_PARAM_DIGSIG			0x9E
#define TC_PARAM_VERFIY			0x9F

#define TC_NAMED_CURVE_P256		0x17
#define TC_NAMED_CURVE_P384		0x18
#define TC_NAMED_CURVE_P521		0x19

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;

#define TC_SECRET_KEY_LABEL_LEN 27
typedef struct {
	char acLabel[TC_SECRET_KEY_LABEL_LEN+1]; // NULL terminated string
	BYTE bKeyType;	// As defined by TC_KEYTYPE_
	BYTE bKeyLen;	// In bytes
	WORD wAttrs;	// Bitmapped field, see TC_ATTR_* defines
	BYTE abKcv[3];	// Key check value
} TC_SECRET_KEY_ATTRS;

#define TC_ATTR_ENCRYPT		0x0080
#define TC_ATTR_DECRYPT		0x0040
#define TC_ATTR_WRAP		0x0020
#define TC_ATTR_UNWRAP		0x0010
#define TC_ATTR_EXTRACT		0x0008
#define TC_ATTR_GENMS		0x0004
#define TC_ATTR_GENSESSION	0x0002
#define TC_ATTR_GENMAC		0x0001

extern int tcVerifyPIN(CK_USER_TYPE userId, BYTE *pbVerificationData);
extern int tcVerifyPIN2(CK_BYTE bPINRef , CK_BYTE *pbVerificationData);
extern int tcSetPIN(CK_USER_TYPE userId, BYTE *pbVerificationData, BYTE *pbNewPin);
extern int tcChangePIN(CK_BYTE bPinRef, CK_BYTE_PTR pSoPIN, CK_BYTE_PTR pNewPIN);
extern int tcSetPINSOLoggedIn(CK_USER_TYPE userId, BYTE *pbNewPin);
extern int tcErasePrivateKey(WORD wEFId);
extern int tcCreateEF(BYTE bPrefix, BYTE bMaxSuffix, WORD wSize, DWORD dwReadAccess, DWORD dwUpdateAccess, WORD *pwEFId);
extern int tcSelectEF(WORD wEFId, WORD *pwFileSize);
extern int tcWriteEF(WORD wEFId, BYTE *pData, WORD wLen);
extern int tcWriteCurrentEF(WORD wOffset, BYTE bNumBytes, BYTE *pBuffer);
extern WORD tcReadCurrentEF(WORD wOffset, WORD wNumBytes, BYTE *pBuffer);
extern int tcReadSecretKeyAttrs(CK_OBJECT_HANDLE hKey, TC_SECRET_KEY_ATTRS *pAttrs);
extern WORD tcReadRsaModulus(WORD wEFId, BYTE *pBuffer, WORD wBuffSize);
extern int tcSelectApp();
extern int tcMseRestore(BYTE bSecurityEnvironmentNumber);
extern int tcMseSetKeyFile(WORD wEFId, BYTE bTemplateID);
extern int tcMseSetCipherSuite(WORD wCipherSuite);
extern int tcMseSetTlsKeyLengths(BYTE bKeyLen, BYTE bMacLen, BYTE bRecordIvLen);
extern int tcMseSetAlgo(BYTE bAlgo, BYTE bTemplateID);
extern int tcEncrypt(BYTE *pPlainText, WORD wPlainLen, BYTE *pIv, BYTE bIvLen, BYTE *pCipherText, WORD *pwCipherLen);
extern int tcEncryptGcm(BYTE *pPlainText, WORD wPlainLen, BYTE *pIv, BYTE bIvLen, BYTE *pAdd, BYTE bAddLen, BYTE *pCipherText, WORD *pwCipherLen);
extern int tcDecrypt(BYTE *pCipherText, WORD wCipherLen, BYTE *pIv, BYTE bIvLen, BYTE *pPlainText, WORD *pwPlainLen);
extern int tcDecryptGcm(BYTE *pCipherText, WORD wCipherLen, BYTE *pIv, BYTE bIvLen, BYTE *pAdd, BYTE bAddLen, BYTE *pPlainText, WORD *pwPlainLen);
extern int tcSign(BYTE *pData, WORD wDataLen, BYTE *pSignature, WORD *pwSigLen);
extern int tcGenerateRsaKey(WORD wEFId, WORD wModulusLenBits);
extern int tcGenerateEcKey(WORD wEFId, BYTE bCurveId, BYTE bEcdhOnly, BYTE *pOut);
extern int tcAskRandom(BYTE bNumBytes, BYTE *pData);
extern int tcShaInit(BYTE bHashLen);
extern int tcShaUpdate(BYTE *abData, WORD wLen);
extern WORD tcShaFinal(BYTE *abData);
extern WORD tcSha(BYTE bHashLen, BYTE *abData, WORD wLen);
extern int tcHandshakeShaInit(BYTE bHashLen);
extern int tcHandshakeShaUpdate(BYTE *abData, WORD wLen);
extern WORD tcHandshakeShaFinal(BYTE *abData);
extern int tcDeleteFile(WORD EFId);
extern int tcGeneratePreMasterSecret(BYTE bTlsMajVer, BYTE bTlsMinVer, CK_OBJECT_HANDLE *EFId);
extern int tcGeneratePreMasterSecretAlgo(BYTE *pOtherPublicKey, WORD wOtherPublicKeyLen, CK_OBJECT_HANDLE *EFId);
extern int tcGenerateMasterSecret(CK_OBJECT_HANDLE wPmsEFId,BYTE bExtended, BYTE *pData, WORD wDataLen, CK_OBJECT_HANDLE *wMsEFId, BYTE *bTlsMajVer, BYTE *bTlsMinVer);
extern int tcGenerateSessionKeys(BYTE *pServerThenClientRandom, CK_OBJECT_HANDLE *hClientWriteMac, CK_OBJECT_HANDLE *hServerWriteMac, CK_OBJECT_HANDLE *hClientWrite, CK_OBJECT_HANDLE *hServerWrite, BYTE *pClientWriteIv, BYTE *pServerWriteIv);
extern int tcGenerateAesKey(BYTE *pLabel, BYTE bLen, WORD wFlags, CK_OBJECT_HANDLE *pEFId);
extern int tcPreloadPublicKey(WORD wEFId);
extern int tcWrapKey(CK_OBJECT_HANDLE hKeyToWrap, BYTE *pOutput, CK_ULONG *pLength);
extern int tcUnwrapKey(WORD wFlags, BYTE *pAesLabel, BYTE *pCheckValue, BYTE bAesKeyLen,BYTE *pWrappedKey,CK_ULONG ulWrappedKeyLen, CK_OBJECT_HANDLE_PTR phKey);
extern int tcVerify(BYTE *pSig, WORD wSigLen);
extern int tcVerifyECDSA(BYTE *pHash, WORD wHashLen, BYTE *pSignature, WORD wSigLen);
extern int tcImportAesKey(BYTE *pLabel, BYTE bLen, WORD wFlags, BYTE *pValue, CK_OBJECT_HANDLE *pEFId);
extern int tcEraseTLSKeys();
extern int tcLoadUntrustedPublicKey(BYTE *pModulus, WORD wModLen, BYTE *pExponent, BYTE bExpLen);
extern int tcLoadUntrustedPublicEccKey(BYTE bCurveId,BYTE *pPubKey, WORD wPubKeyLen);
extern int tcGetVersion(BYTE *pbMajor, BYTE *pbMinor);

#ifdef __cplusplus
}

#endif
#endif /* TC_API_H_ */
