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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define maxDataSize 249
#define APDU_TIMEOUT 10000

extern unsigned short multosSendAPDU(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned short Lc, unsigned short Le, unsigned short *La, unsigned char case4, unsigned char *data, int dataBuffLen, unsigned long maxWait);

static int loadComponent(unsigned char INS, unsigned char *component, unsigned short complen)
{
	unsigned short offset = 0;
	unsigned char chunksize;
	unsigned short SW;
	unsigned char P1,P2;
	unsigned short La;

	while(complen > 0)
	{
		// Work out how much of the component to send
		chunksize = complen;
		if(complen > maxDataSize)
			chunksize = maxDataSize;

		// Work out P1 and P2 values
		P1 = offset / 256;
		P2 = offset % 256;

		// Send command
		SW = multosSendAPDU(0xBE,INS,P1,P2,chunksize,0,&La,0,component + offset, chunksize, APDU_TIMEOUT);
		if(SW != 0x9000)
			return(0);

		// Move on to next chunk
		complen = complen - chunksize;
		offset = offset + chunksize;
	}
	return(1);
}

static int openMelApp(unsigned char *alc, unsigned short staticSize, unsigned short sigSize, unsigned short ktuSize)
{
    unsigned char data[255];
    unsigned short La;
    unsigned short SW;
    unsigned short offset = 26;

    // Set up data needed using ALC data but static size from the ALU
    memcpy(data,alc+offset,126);
    offset = offset + 126;
    data[122] = staticSize / 256;
    data[123] = staticSize % 256;
    data[126] = sigSize / 256;
    data[127] = sigSize % 256;
    data[128] = ktuSize / 256;
    data[129] = ktuSize % 256;
    memcpy(data+130,alc+offset,4);
    offset = offset + 4;
    memcpy(data+134,alc+offset+3,23);

    // Send APDU
    SW = multosSendAPDU(190,18,0,0,157,0,&La,1,data, sizeof(data), APDU_TIMEOUT);

    // Check reply. Should be 0x9000 or 0x61nn
    if(SW == 0x9000 || ((SW >> 8) == 0x61))
    	return(1);
    else
    	return(0);
}

/// Send a binary ALC or ADC.
/// loadNotDelete = 1 for ALC, = 0 for ADC
/// Returns 1 if success, 0 if failure
static int sendCertificate(unsigned char loadNotDelete, unsigned char *certificate, int certlen)
{
	unsigned char INS = 24; // Default to delete
	unsigned short offset = 0;
	unsigned short SW;
	unsigned char chunksize;
	unsigned short La;

	if(loadNotDelete)
		INS = 22;

	while(certlen > 0)
	{
		// Work out how much of the cert to send
		chunksize = certlen;
		if(certlen > maxDataSize)
			chunksize = maxDataSize;

		// Send command
		SW = multosSendAPDU(0xBE,INS,0,0,chunksize,0,&La,0,certificate + offset,chunksize, APDU_TIMEOUT);
		if(SW != 0x9000)
			return(0);

		// Move on to next chunk
		certlen = certlen - chunksize;
		offset = offset + chunksize;
	}
	return(1);
}

static void getAluSizes(unsigned char *alu, unsigned short *staticSize, unsigned short *sigSize, unsigned short *ktuSize)
{
    unsigned short offset = 8; // Skip MCD_NUMBER
    unsigned short seglen = 0;

    // Skip Code
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2 + seglen;

    // Data is next
    seglen = alu[offset] * 256 + alu[offset+1];
    *staticSize = seglen;
    offset = offset + 2 + seglen;

    // Skip DIR
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2 + seglen;

    // Skip FCI
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2 + seglen;

    // SIG is next
    seglen = alu[offset] * 256 + alu[offset+1];
    *sigSize = seglen;
    offset = offset + 2 + seglen;

    // KTU is next
    seglen = alu[offset] * 256 + alu[offset+1];
    *ktuSize = seglen;
    offset = offset + 2 + seglen;
}

static int loadAlu(unsigned char *alu)
{
    unsigned short offset = 8; // Skip MCD_NUMBER
    unsigned short seglen = 0;

    // Load Code
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (! loadComponent(36,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    // Load Data
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (! loadComponent(38,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    // Load DIR
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (!loadComponent(32,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    // Load FCI
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (! loadComponent(34,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    // Load SIG
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (! loadComponent(40,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    // Load KTU
    seglen = alu[offset] * 256 + alu[offset+1];
    offset = offset + 2;
    if(seglen > 0)
    	if (! loadComponent(42,alu+offset,seglen))
    		return(0);
    offset = offset + seglen;

    return(1);
}

int multosLoadApp(char *aluFile, char *alcFile, char *error, int errBuffLen)
{
	FILE *fp;
	long alcSize, aluSize;
	unsigned char *alc, *alu;
	int status = 1;
	unsigned short staticSize,sigSize,ktuSize;

	// Read ALC
	fp = fopen(alcFile,"rb");
	if(fp == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to open ALC\n");
		return(0);
	}
	fseek(fp,0,2);
	alcSize = ftell(fp);
	fseek(fp,0,0);
	alc = (unsigned char *)malloc(alcSize);
	if(alc == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to read ALC\n");
		return(0);
	}
	fread(alc,1,alcSize,fp);
	fclose(fp);

	// Read ALU
	fp = fopen(aluFile,"rb");
	if(fp == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to open ALU\n");
		free(alc);
		return(0);
	}
	fseek(fp,0,2);
	aluSize = ftell(fp);
	fseek(fp,0,0);
	alu = (unsigned char *)malloc(aluSize);
	if(alu == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to read ALU\n");
		free(alc);
		return(0);
	}
	fread(alu,1,aluSize,fp);
	fclose(fp);

	// Get lengths from the ALU
	getAluSizes(alu, &staticSize, &sigSize, &ktuSize);

	// Open MEL App using ALC info and ALU static size
	if(!openMelApp(alc,staticSize,sigSize,ktuSize))
	{
		if(error) snprintf(error,errBuffLen-1,"Open MEL Application failed\n");
		free(alc);
		return(0);
	}

	// Load ALU
	if(!loadAlu(alu))
	{
		if(error) snprintf(error,errBuffLen-1,"ALU loading failed\n");
		status = 0;
	}

	// Load ALC
	if(status && !sendCertificate(1,alc,alcSize))
	{
		if(error) snprintf(error,errBuffLen-1,"ALC loading failed\n");
		status = 0;
	}

	// Cleanup and exit
	free(alc);
	free(alu);
	return(status);
}

int multosDeleteApp(char *adcFile, char *error, int errBuffLen)
{
	FILE *fp;
	long adcSize;
	unsigned char *adc;
	int status = 1;

	// Read ADC
	fp = fopen(adcFile,"rb");
	if(fp == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to open ADC\n");
		return(0);
	}
	fseek(fp,0,2);
	adcSize = ftell(fp);
	fseek(fp,0,0);
	adc = (unsigned char *)malloc(adcSize);
	if(adc == NULL)
	{
		if(error) snprintf(error,errBuffLen-1,"Failed to read ADC\n");
		return(0);
	}
	fread(adc,1,adcSize,fp);
	fclose(fp);

	if(!sendCertificate(0,adc,adcSize))
	{
		status = 0;
		if(error) snprintf(error,errBuffLen-1,"ADC loading failed\n");
	}
	free(adc);
	return(status);
}
