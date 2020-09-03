/*
 * Copyright (c) 2020, MAOSCO Ltd
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

#include <sys/types.h>		// Used for Shared Memory
#include <sys/ipc.h>		// Used for Shared Memory
#include <sys/shm.h>		// Used for Shared Memory
#include <multosShared.h>

extern void multosHexToBin(char *hexIn, unsigned char *binOut, int len);

unsigned short multosSendAPDU(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned short Lc, unsigned short Le, unsigned short *La, unsigned char case4, unsigned char *data, int dataBuffLen, unsigned long maxWait)
{
	DWORD wait = 0;
	WORD sw12 = 0;
	DWORD myPid = 0;
	multosShared_t *sharedMem = NULL;
	key_t sharedMemKey;
	int sharedMemId;

	myPid = getpid();

	// Attach to shared memory segment if needed
	if(sharedMem == NULL)
	{
		sharedMemKey = ftok(MULTOS_SHARED_MEM_LOC,'R');
		sharedMemId = shmget(sharedMemKey,sizeof(multosShared_t),0);
		sharedMem = (multosShared_t*)shmat(sharedMemId,NULL,0);
		if((void*)sharedMem == (void*)-1)
		{
			fprintf(stderr,"Failed to open shared memory\n");
			return(0xFFFF);
		}
	}

	// Wait for MULTOS device to be available
	while(wait < maxWait && sharedMem->status != AVAILABLE)
	{
		wait += 10;
		usleep(10000);
	}
	if(sharedMem->status != AVAILABLE)
	{
		shmdt(sharedMem);
		return(0xFFFF);
	}

	// Request it
	sharedMem->requestingPid = myPid;
	sharedMem->status = REQUESTED;

	// Wait for confirmation
	while(wait < maxWait && sharedMem->status != CONNECTED)
	{
		wait += 10;
		usleep(10000);
	}
	if(sharedMem->status != CONNECTED || sharedMem->connectedPid != myPid)
	{
		shmdt(sharedMem);
		return(0xFFFF);
	}

	// Prepare message in shared memory
	sharedMem->CLA = CLA;
	sharedMem->INS = INS;
	sharedMem->P1 = P1;
	sharedMem->P2 = P2;
	sharedMem->Lc = Lc;
	sharedMem->Le = Le;
	sharedMem->case4 = case4;
	sharedMem->timeout = maxWait;
	if(Lc > 0 && data)
		memcpy(sharedMem->data,data,Lc <= MULTOS_SHARED_MAX_DATA ? Lc : MULTOS_SHARED_MAX_DATA);

	// Trigger the processing
	sharedMem->status = CMD_READY;
	usleep(50000);

	// Wait for a reply
	wait = 0;
	while(wait < maxWait && sharedMem->status != RESULT_AVAILABLE)
	{
		wait += 10;
		usleep(10000);
	}

	if(sharedMem->status == RESULT_AVAILABLE && sharedMem->connectedPid == myPid)
	{
		sw12 = sharedMem->SW12;
		if(La != NULL)
			*La = sharedMem->La;
		if(*La > 0 && data != NULL)
			memcpy(data,sharedMem->data,*La <= dataBuffLen ? *La : dataBuffLen);

		// Tell daemon we're done and wait for confirmation of disconnection
		sharedMem->requestingPid = myPid;
		sharedMem->status = DISCONNECT;

		wait = 0;
		while(wait < maxWait && sharedMem->connectedPid != 0)
		{
			wait += 10;
			usleep(10000);
		}
		if(sharedMem->connectedPid != 0)
			sw12 = 0xFFFF;
	}
	else
	{
		// Something went wrong.
		sw12 = 0xFFFF;
	}

	shmdt(sharedMem);
	return(sw12);
}

int multosSelectApplication (char *hexAid)
{
	unsigned char aidLen;
	unsigned short La;
	unsigned short sw;
	unsigned char aid[16];

	aidLen = strlen(hexAid) / 2;
	if(aidLen > 16)
		aidLen = 16;
	multosHexToBin(hexAid,aid,aidLen);

	sw = multosSendAPDU(0,0xA4,0x04,0x0C,aidLen,0,&La,0,aid,sizeof(aid),1000);
	if(sw == 0x9000)
		return(1);
	return(0);
}

int multosDeselectCurrApplication()
{
	unsigned char aid[] = { 0x3F, 0x00 };
	unsigned short La;
	unsigned short sw;

	sw = multosSendAPDU(0,0xA4,0,0,2,0,&La,0,aid,sizeof(aid),1000);
	if(sw == 0x9000)
		return(1);
	return(0);
}

int multosInit(void)
{
	// Nothing to do
	return(1);
}

int multosReset(void)
{
	unsigned short La;
	unsigned short sw;

	sw = multosSendAPDU(0xBE,0xFF,0,0,0,0,&La,0,NULL,0,20000);
	if(sw == 0x9000)
		return(1);
	return(0);
}
