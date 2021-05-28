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

// Platform specific code.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "platform.h"

extern void multosHexToBin(char *hexIn, unsigned char *binOut, int len);
extern void multosBinToHex(unsigned char* binIn, char* hexOut, int len);

#define CLIENT_TIMEOUT		5000000
#define I2C_IF_I2C_CLOCK_SPEED 0x70

static unsigned char abBuffer[4000];
HANDLE serialStream = INVALID_HANDLE_VALUE;
static OVERLAPPED ov_write = {0};
static unsigned char i2cBufMsg[] = { 0x55, 0xBE, 0x83, 0x02, 0x00, MASTER_I2C_BUF_SIZE };
static char hex[8000];
static char msgBuf[256];
static char serialPortPath[16] = "COM20";

// If you have connected the USB-ISS module's I/O1 pin to the MULTOS chip's RST line, or you have a dongle that supports hardware reset, uncomment the following line
//#define HARD_RESET

// Constants for the transport protocol. Do not remove or change.
#define MULTOS_RESPONSE_TAG_REG 0x80
#define MULTOS_MASTER_I2C_BUFSIZE_REG 0x83

// ----------------------- Local functions -----------------------------------------

// Support function for outputing messages.
static void traceMessage(char *msg)
{
    time_t timer;
    char buffer[26];
    struct tm* tm_info;

	time(&timer);
	tm_info = localtime(&timer);

	strftime(buffer, 26, "%d-%m-%Y %H:%M:%S", tm_info);

	fprintf(stdout,"%s %s\n",buffer,msg);
	fflush(stdout);
}

// Reads the COM port in a non-blocking way.
static int
readMessage(unsigned char *buff, HANDLE comport, DWORD nExpected, DWORD maxWaitTime)
{
	int offset = 0;
	DWORD nActual = 0;
	BOOL waitingOnRead = FALSE;
	OVERLAPPED ov_read = {0};
	int numWaits = 0;
	DWORD sleepTime = 5;
	int maxWaits = maxWaitTime / sleepTime;
	int b;

	ov_read.hEvent = CreateEventA(NULL,TRUE,FALSE,NULL);
	if(ov_read.hEvent == NULL)
	{
		sprintf(msgBuf,"Read: CreateEvent failed, error %d\n",GetLastError());
		traceMessage(msgBuf);
		return(0);
	}
	do
	{
		if(!waitingOnRead)
		{			
			if(!ReadFile(comport,buff + offset,nExpected-nActual,&nActual,&ov_read))
			{			
				DWORD err = GetLastError();
				if (err != ERROR_IO_PENDING)
				{
					return (0);
				}
				else
					waitingOnRead = TRUE;
			}
			else
			{
				if(nActual == 0)
				{
					Sleep(sleepTime);
					numWaits++;
				}
				else
				{
					offset += nActual;
				}
			}
		}
					
		if(waitingOnRead)
		{
			DWORD res = WaitForSingleObject(ov_read.hEvent, maxWaitTime);
			switch(res)
			{
				case WAIT_OBJECT_0:
					if (GetOverlappedResult(comport,&ov_read,&nActual,FALSE))
					{
						offset += nActual;
						numWaits = 0;						
					}
					else
					{
						sprintf(msgBuf,"\nRead wait error, code %d\n",GetLastError());
						traceMessage(msgBuf);
					}
					waitingOnRead = FALSE;	
					break;

				case WAIT_TIMEOUT:
					numWaits = maxWaits;
					break;

				default:
					break;
			}
		}	
		ResetEvent(ov_read.hEvent);
	} while(offset < nExpected && numWaits < maxWaits);	
	CloseHandle(ov_read.hEvent);
	/*
	if(offset > 0)
	{
		printf("Read: ");
		for(b=0;b<offset;b++)
			printf("%02x",buff[b]);
		printf("\n");
	}
	*/
	return(offset);
}

// Reset when running in command mode
static int reset(HANDLE comport)
{
	DWORD nActual;
	int nread = 0;
	int ret = 0;
	int waits = 0;	
	unsigned char i2cResetMsg[] = { 0x55, 0xBE, 0x00, 0x01, 0x06 };

#ifdef HARD_RESET
	// Dip reset line momentarily low
	unsigned char buff[] = { 0x5A, 0x02, I2C_IF_I2C_CLOCK_SPEED, 0x00 };
	WriteFile(serialStream,buff,4,&nActual,&ov_write);
	Sleep(20);
	nActual = readMessage(buff,comport,2,1000);
	if(nActual == 2 && buff[0] == 0xFF && buff[1] == 0x00)
	{
		unsigned char buff2[] = { 0x5A, 0x02, I2C_IF_I2C_CLOCK_SPEED, 0x01 };
		WriteFile(serialStream,buff2,4,&nActual,&ov_write);
		Sleep(20);
		nActual = readMessage(buff,comport,2,1000);
		if(!(nActual == 2 && buff[0] == 0xFF && buff[1] == 0x00))
			return 0;
		ret = 1;
	}
#else
	// Send soft reset command to MULTOS
	writeToI2C(i2cResetMsg,sizeof(i2cResetMsg),TRUE);
	ret = 1;
#endif

	// Wait for MULTOS to restart
	memset(abBuffer,0,8);
	Sleep(100);

	// Send device I2C buffer size to MULTOS again as it will have forgotten it in the reset.	
	writeToI2C(i2cBufMsg,sizeof(i2cBufMsg),TRUE);
	Sleep(5);

	return(ret);
}

// Opens the USB-ISS device (which looks like a serial port to the PC)
static int openSerialPort(void)
{
	char portNum[8];
	char portPath[64];
	int portnum = 0;
	COMMTIMEOUTS comTimeOut; 
	DWORD nActual;
	unsigned char buff[] = { 0x5A, 0x02, I2C_IF_I2C_CLOCK_SPEED, 0x01 };
	WCHAR wcEnvVar[128];
	char envVar[64];
	DWORD copied;

	// See if the serial port is specified in the environment
	if((copied = GetEnvironmentVariableW(L"MULTOS_I2C_COMPORT",wcEnvVar,sizeof(envVar))) > 0)
	{
		wcstombs_s((size_t*)&nActual,envVar,sizeof(envVar),wcEnvVar,(size_t)copied);
		memcpy(serialPortPath,envVar,copied);
	}
	else
		fprintf(stderr,"\nWarning: MULTOS_I2C_COMPORT environment variable not set. Using default %s\n",serialPortPath);

	// Sort out the correct windows name for the port
	portnum = atoi(serialPortPath+3);
	if(portnum > 9)
		sprintf(portPath,"\\\\.\\COM%d",portnum);
	else
		sprintf(portPath,"COM%d",portnum);

	// Close stream if already open.
	if(serialStream != INVALID_HANDLE_VALUE)
	{
		CloseHandle(serialStream);
		serialStream = INVALID_HANDLE_VALUE;
	}

	serialStream = CreateFileA( portPath,
								GENERIC_READ|GENERIC_WRITE,
								0,
								NULL,
								OPEN_EXISTING,
								FILE_FLAG_OVERLAPPED,
								//0,
								NULL);

	if(serialStream == INVALID_HANDLE_VALUE)
		return(0);

	// ..and configure it

	// Set clock speed + IO/1 to output high
	WriteFile(serialStream,buff,4,&nActual,&ov_write);
	Sleep(20);

	// Check for the return status
	nActual = readMessage(buff,serialStream,2,1000);
	if(!(nActual == 2 && buff[0] == 0xFF && buff[1] == 0x00))
	{
		sprintf(msgBuf,"i2c device failed to initialise\n");
		traceMessage(msgBuf);
		return 0;
	}

	// Send device I2C buffer size to MULTOS
	writeToI2C(i2cBufMsg,sizeof(i2cBufMsg),TRUE);

	return(1);
}

// ----------------------- External functions --------------------------------------
int readI2C(unsigned char *reply, int len, unsigned long maxWait)
{
	return (readMessage(reply,serialStream,len,maxWait));
}

// Send one block of data over I2C interface
void writeToI2C(unsigned char *buff, int len, BOOL getAck)
{
	DWORD nActual = 0;
	unsigned char ACK[1];
	int i;

	/*
	printf("Write: ");
	for(i=0;i<len;i++)
		printf("%02x",buff[i]);
	printf("\n");
	*/

	WriteFile(serialStream,buff,len,&nActual,&ov_write);

	// Check for ACK from I2C writes
	if(getAck)
	{
		nActual = readMessage(ACK,serialStream,1,1000);
		if(nActual == 0)
			printf("Missing Write ACK\n");
		else if(nActual > 1)
			printf("Wrong Write ACK - %d read, %02x 1st byte\n",nActual,ACK[0]);
		else if(ACK[0] != 1)
			printf("Wrong Write ACK %02x\n",ACK[0]);
	}	
}

int multosInit(void)
{
	// Try to open the i2c device
	return openSerialPort();
}

int multosReset(void)
{
	return (reset(serialStream));
}
