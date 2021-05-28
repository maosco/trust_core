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

/** This is the Windows version that makes use of the USB-ISS module available from http://www.robot-electronics.co.uk/htm/usb_iss_tech.htm
* It also supports the DigiSeq MULTOS P5 Dongle
*/
#ifndef MULTOSIO_H_
#define MULTOSIO_H_

#ifdef __cplusplus
extern "C" {
#endif

// Library version that can be used by applications linking this library.
#define MULTOSIO_VERSION_DESC	"multosio_i2c.lib (Windows)"
#define MULTOSIO_VERSION_MAJOR	((unsigned char) 1)
#define MULTOSIO_VERSION_MINOR ((unsigned char) 0)
extern void multosHALInfo(char *desc, unsigned char *major, unsigned char *minor);

/// Send APDU given by CLA, INS, P1, P2, Lc, Le and data
/// dataBuffLen is the size of the buffer 'data' (in unsigned chars)
/// case4 should set to 1 if Lc and Le are both valid
/// La set on return to indicate the amount of return data
/// Returns the APDU response status word or 0x0000 if there is a comms error
/// maxWait is the maximum wait time in milliseconds to receive a reply.
extern unsigned short multosSendAPDU(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned short Lc, unsigned short Le, unsigned short *La, unsigned char case4, unsigned char *data, int dataBuffLen, unsigned long maxWait);

/// Load a MULTOS application from its .alu and .alc formatted file.
/// 'error' MUST point to a char buffer of errBuffLen unsigned chars long.
/// Returns 1 if app loads OK, 0 if there is an error (message placed into error)
extern int multosLoadApp(char *aluFile, char *alcFile, char *error, int errBuffLen);

/// Delete a MULTOS application using an .adc formatted file.
/// 'error' MUST point to a char buffer of errBuffLen unsigned chars long.
/// Returns 1 if app deletes OK, 0 if there is an error (message placed into error)
extern int multosDeleteApp(char *adcFile, char *error, int errBuffLen);

/// Select a MULTOS application using its application ID (AID)
/// Returns 1 if selected OK, 0 if not.
extern int multosSelectApplication (char *hexAid);

/// Deselect current application - reselects the OS
extern int multosDeselectCurrApplication(void);

/// Initialises the interface to the MULTOS device
/// Returns 1 if initialised OK, 0 if not
extern int multosInit(void);

/// Reset the MULTOS device
/// Returns 1 if reset successful, 0 otherwise
extern int multosReset(void);

// Bit specifiers to be used for requestByte and validFields below
#define MCDNO_VALID 1
#define MKDPKC_VALID 2
#define REMAIN_E2_VALID 4
#define APPDATA_VALID 8
#define BUILDNO_VALID 16

typedef struct
{
	unsigned char aidLen;
	unsigned char aid[16];
	unsigned long appSize;
} multosAppData_t;

#define MULTOS_MAX_APPS 12
#define MULTOS_MAX_MCDNUM_LEN 8
#define MULTOS_MAX_PKC_LEN 256
#define MULTOS_MAX_BUILDNUM_LEN 4

typedef struct
{
	unsigned char validFields;
	unsigned char mcdNumber[MULTOS_MAX_MCDNUM_LEN];
	unsigned char mkdPkC[MULTOS_MAX_PKC_LEN];
	unsigned short mkdPkCLen;
	unsigned long remainingE2size;
	unsigned char numApps;
	unsigned char buildNumber[MULTOS_MAX_BUILDNUM_LEN];
	multosAppData_t apps[MULTOS_MAX_APPS];
} multosChipData_t;

/// Return the requested chip information in 'data' as specified by the bits set in 'requestByte'
extern void multosGetChipInfo(unsigned char requestByte,multosChipData_t *data);


// Misc utility functions
extern void multosBinToHex(unsigned char* binIn, char* hexOut, int len);
extern void multosHexToBin(char *hexIn, unsigned char *binOut, int len);
extern void multosWordToHex(unsigned short w, char* hexOut);

#ifdef __cplusplus
}
#endif

#endif /* MULTOSIO_H_ */
