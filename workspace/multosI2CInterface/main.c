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
 ** Interface for using the Multos International P22 in command-mode over the i2c port via a shared memory interface
 ** Use in conjunction with the appropriate multosio.so library
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/types.h>		// Used for Shared Memory
#include <sys/ipc.h>		// Used for Shared Memory
#include <sys/shm.h>		// Used for Shared Memory
#ifdef WIRINGPI
#include <wiringPi.h>		// GPIO
#include <wiringPiI2C.h>   // I2C
#else
#include <pigpiod_if2.h>
#endif
#include <unistd.h>		// For read and write

#include "multosShared.h"
#include "utils.h"

#define SHORT_DELAY			5000
#define LONG_DELAY			10000
#define CLIENT_TIMEOUT		50000000


#define MULTOS_SLAVE_DEVICE 0x5F

#ifdef WIRINGPI
// Physical pin numbering scheme
#define MULTOS_RESET_PIN 11
#define SCL_MONITOR_PIN 13
#else
// Broadcom GPIO PIN numbers
// Use shell command "pinout" to get the numbers
#define MULTOS_RESET_PIN 17
#define SCL_MONITOR_PIN 27

// Daemon connection ID
int pi = 0;

// Version of Raspbian
int raspbian = 0;

#endif

static BYTE buffer[MULTOS_SHARED_MAX_DATA+20]; // Big enough to contain a full APDU formatted in P22 serial/i2c interface style
static char hex[600];
static char msgBuf[256];

// The I2C buffer sizes vary from device to device. On the Arduino UNO and RPi its 64 unsigned chars.
// MULTOS has to be told this size so that it doesn't send back too much in one go.
// The value here is a bit less than the maximum to allow for the header bytes of the protocol.
#define MASTER_I2C_BUF_SIZE 60

// Definitions of the MULTOS Command Mode I2C registers
#define MULTOS_TAGLEN_REG       0
#define MULTOS_VALUE_REG        1
#define MULTOS_RESPONSE_TAG_REG 0x80
#define MULTOS_RESPONSE_TAG_LEN 0x81
#define MULTOS_RESPONSE_TAG_VAL 0x82
#define MULTOS_MASTER_I2C_BUFSIZE_REG 0x83

#define MULTOS_TAGLEN_REG_LEN   3 // Tag(1) + Len(2)

// File Descriptor for I2C connection
int i2cFd = -1;


void traceMessage(char *msg)
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

// ------------------------------ I2C support functions ----------------------------
// This function is needed because the RPi doesn't support i2c clock stretching
// The idea is to start the first read of a response which causes the slave to stretch
// the clock until it has a reply ready. This function detects the clock going high again.
#ifdef WIRINGPI
// Normal reading can then resume.
static int waitI2C(unsigned long maxWait)
{
	unsigned long waitTimeLeft = maxWait * 1000;
	int waitNeeded;

	char c = MULTOS_RESPONSE_TAG_REG;
	write(i2cFd,&c,1);
	read(i2cFd,&c,1);
	usleep(5);
	waitNeeded = 1 - digitalRead(SCL_MONITOR_PIN);
	//printf("->%d %02x\n",waitNeeded,c);
    while(digitalRead(SCL_MONITOR_PIN) == 0 && waitTimeLeft > 0)
    {
	  usleep(100);
	  waitTimeLeft -= 100;
    }
    if(waitTimeLeft > 0)
    {
	if(waitNeeded || c == MULTOS_RESPONSE_TAG_REG)
	  read(i2cFd,&c,1);
	//printf("%02x\n",c);
    	return (c);
    }
    fprintf(stderr,"Timeout\n");
    fflush(stderr);
    return(-1);
}

// If porting to a platform other than the Pi, change this function
static int readI2C(unsigned char *reply, int len)
{
  int i = 0;

  i = read(i2cFd,reply,len);

  return (i);
}

// Send one block of data over I2C interface
// If porting to a platform other than the Pi, change this function
static int writeToI2C(unsigned char *buff, int len)
{
	int n = write(i2cFd,buff,len);
	usleep(10);
	return n;
}

int reset()
{
	unsigned char bufferSizeMessage[] = { MULTOS_MASTER_I2C_BUFSIZE_REG, 0x00, MASTER_I2C_BUF_SIZE };

	// Do a reset - Falling edge on reset pin whilst MULTOS M5 pin 18 is held high
	digitalWrite(MULTOS_RESET_PIN,LOW);
	delay(10);
	digitalWrite(MULTOS_RESET_PIN,HIGH);

	// Wait for MULTOS to reboot
	delay(20);

	// Tell MULTOS how big this device's i2c message buffer is
	writeToI2C(bufferSizeMessage,sizeof(bufferSizeMessage));

	return(1);
}
#else
int waitI2C(unsigned long maxWait)
{
	unsigned long waitTimeLeft = maxWait * 1000;
	int val;

	i2c_write_byte(pi,i2cFd,MULTOS_RESPONSE_TAG_REG);
	val = i2c_read_byte(pi,i2cFd);
	usleep(5);

    while(gpio_read(pi,SCL_MONITOR_PIN) == 0 && waitTimeLeft > 0)
    {
	  usleep(100);
	  waitTimeLeft -= 100;
    }

    if(waitTimeLeft > 0)
    {
		if (val < 0)
		{
			if (raspbian != 11)
				val = i2c_read_byte(pi,i2cFd);

			val = MULTOS_RESPONSE_TAG_LEN;
		}
    	return (val);
    }

    fprintf(stderr,"Timeout\n");
    fflush(stderr);
    return(-1);
}

int readI2C(unsigned char *reply, int len)
{
  int i = 0;

  i = i2c_read_device(pi, i2cFd,(char*)reply,len);

  if (i < 0)
	  i = 0;

  return (i);
}

// Send one block of data over I2C interface
int writeToI2C(unsigned char *buff, int len)
{
	int n = i2c_write_device(pi,i2cFd,(char*)buff,len);
	usleep(10);

	// If write OK, return number of bytes
	if(n == 0)
		n = len;

	return n;
}

int reset(void)
{
	  unsigned char bufferSizeMessage[] = { MULTOS_MASTER_I2C_BUFSIZE_REG, 0x00, MASTER_I2C_BUF_SIZE };

	  // Do a reset - Falling edge on reset pin whilst MULTOS M5 pin 18 is held high
	  gpio_write(pi,MULTOS_RESET_PIN, 0);
	  usleep(10000);
	  gpio_write(pi,MULTOS_RESET_PIN, 1);

	  // Wait for MULTOS to reboot
	  usleep(20000);

	  // Tell MULTOS how big this device's i2c message buffer is
	  writeToI2C(bufferSizeMessage,sizeof(bufferSizeMessage));

	  return(1);
}
#endif

// Take an APDU formatted in the MULTOS Command Mode format and send it over
// the i2c interface, in blocks as needed
static void sendAPDUOverI2C(unsigned char *buff, int toSend)
{
  unsigned char i2cbuff[MASTER_I2C_BUF_SIZE];
  int b;

  // Send the TAG and LENGTH from the incoming buffer to appropriate register of the MULTOS i2c interface
  i2cbuff[0] = MULTOS_TAGLEN_REG;
  memcpy(i2cbuff+1,buff,MULTOS_TAGLEN_REG_LEN);
  writeToI2C(i2cbuff,MULTOS_TAGLEN_REG_LEN+1);

  // Send the command DATA to register 1, in chunks as needed
  if(toSend > MULTOS_TAGLEN_REG_LEN)
  {
    int dataLen = toSend - MULTOS_TAGLEN_REG_LEN;
    i2cbuff[0] = MULTOS_VALUE_REG; // Change to the value register

    const int maxDataPerBlock = MASTER_I2C_BUF_SIZE - 4;

    int numBlocks = dataLen / maxDataPerBlock;
    int remain = dataLen % maxDataPerBlock;
    for(b=0;b<numBlocks;b++)
    {
      memcpy(i2cbuff+1,buff+MULTOS_TAGLEN_REG_LEN+(b*maxDataPerBlock),maxDataPerBlock);
      writeToI2C(i2cbuff,maxDataPerBlock+1);
    }
    if(remain)
    {
      memcpy(i2cbuff+1,buff+MULTOS_TAGLEN_REG_LEN+(numBlocks*maxDataPerBlock),remain);
      writeToI2C(i2cbuff,remain+1);
    }
  }
}

// Read an APDU reply from MULTOS
static int readI2CReply(unsigned char *buff, unsigned short bufLen, unsigned long maxWait)
{
  int nread = 0;
  int nActual = 0;
  int b = 0;
  unsigned char i2cbuff[8];

  // *** RPi doesn't support i2c clock stretching well. This is a hack to get around that.
  // It returns the response tag contained in MULTOS_RESPONSE_TAG_REG
  if((b = waitI2C(maxWait)) == -1)
    return(0);

  // First request the tag from MULTOS
  //i2cbuff[0] = MULTOS_RESPONSE_TAG_REG; // Register containing tag
  //writeToI2C(i2cbuff,1);
  //nActual = readI2C(buff,1);
  nActual = 1;
  buff[0] = b;

  if(nActual > 0)
	  nread += nActual;

  if(nActual > 0 && buff[0] > 0x3F && buff[0] <= 0xBF)
  {
    // Request length from length register
    unsigned char lengthLength = 2;
    if(buff[0] < 0x80)
      lengthLength = 1;

    i2cbuff[0] = MULTOS_RESPONSE_TAG_LEN; // Register containing length
    writeToI2C(i2cbuff,1);
    nActual = readI2C(buff+nread,lengthLength);
    nread += nActual;

    // Calculate the length of the response data
    int responseLength = buff[1];
    if(lengthLength == 2)
      responseLength = (responseLength << 8) + buff[2];

    // Check that we're not going to blow up the buffer we are reading into
    if(responseLength > bufLen)
    {
    	fprintf(stderr,"i2c read error: response length %d too long for buffer\n",responseLength);
    	fflush(stderr);
    	return(0);
    }

    // Read response in blocks
    int numBlocks = responseLength / MASTER_I2C_BUF_SIZE;
    int remain = responseLength % MASTER_I2C_BUF_SIZE;
    i2cbuff[0] = MULTOS_RESPONSE_TAG_VAL; // Register containing response
    for(b = 0; b < numBlocks; b++)
    {
      writeToI2C(i2cbuff,1); // Read the response
      nActual = readI2C(buff+nread,MASTER_I2C_BUF_SIZE);
      nread += nActual;
    }
    if(remain)
    {
      writeToI2C(i2cbuff,1);
      nActual = readI2C(buff+nread,remain);
      nread += nActual;
    }
  }

  return nread;
}

int main(int argc, char *argv[])
{
	multosShared_t *sharedMem;
	key_t sharedMemKey;
	int sharedMemId;
	useconds_t delay = LONG_DELAY;
	int offset = 0;
	int sendLen = 0;
	int nTotal;
	BYTE inErrorState = 0;
	DWORD connectedPid = 0;
	useconds_t clientTimeOut = CLIENT_TIMEOUT;
	BYTE lastStatus = 255;
	BYTE trace = 1;
	FILE *fp;
	char line[128];

	if(argc == 2)
	{
		if(strcmp(argv[1],"-v") == 0)
		{
			printf("Version: 1.1\n");
			return(0);
		}
		else if ( !isdigit(argv[1][0]) )
		{
			sprintf(msgBuf,"Missing or incorrect single digit argument, 'trace level'");
			traceMessage(msgBuf);
			return(1);
		}
		trace = atoi(argv[1]);
	}

	// Get the Raspbian version
	fp = fopen("/etc/issue","r");
	if (fp)
	{
		fgets(line,sizeof(line),fp);
		fclose(fp);
		if (strncmp(line,"Raspbian GNU/Linux 11",21) == 0)
			raspbian = 11;
	}

	// Create shared memory segment and attach to it
	sharedMemKey = ftok(MULTOS_SHARED_MEM_LOC,'R');
	sharedMemId = shmget(sharedMemKey,sizeof(multosShared_t),0666 | IPC_CREAT);
	sharedMem = (multosShared_t*)shmat(sharedMemId,NULL,0);
	if((void*)sharedMem == (void*)-1)
	{
		sprintf(msgBuf,"Failed to open shared memory key %d",sharedMemKey);
		traceMessage(msgBuf);
		sprintf(msgBuf,"Use ipcrm -M %d to remove shared memory segment",sharedMemKey);
		traceMessage(msgBuf);
		return(1);
	}

	// Initialise shared memory
	sharedMem->status = OFFLINE;
	sharedMem->connectedPid = 0;
	sharedMem->requestingPid = 0;
#ifdef WIRINGPI
	// Set up GPIO
	if(wiringPiSetupPhys() == -1)
	{
		fprintf(stderr,"Failed to initialise GPIO.\n");
		return(1);
	}

	// The RPi doesn't support i2c clock stretching. This is a hack to use another
	// pin to monitor the clock in the function waitI2C()
	pinMode(SCL_MONITOR_PIN,INPUT);

	// Set up reset pin (falling edge triggers a reset on MULTOS when running in embedded mode)
	pinMode(MULTOS_RESET_PIN,OUTPUT);
	digitalWrite(MULTOS_RESET_PIN, 1);
	sleep(1);

	// Connect to I2C device
	i2cFd = wiringPiI2CSetup(MULTOS_SLAVE_DEVICE);

	if(i2cFd < 0)
		return (1);
#else
	// Set up GPIO using local daemon
	pi = pigpio_start(NULL,NULL);
	if(pi < 0)
	{
		fprintf(stderr,"Failed to to connect to pigpiod.\n");
		return(0);
	}

	// The RPi doesn't support i2c clock stretching. This is a workaround to use another
	// pin to monitor the clock in the function waitI2C()
	set_mode(pi,SCL_MONITOR_PIN,PI_INPUT);

	// Set up reset pin (falling edge triggers a reset on MULTOS)
	set_mode(pi,MULTOS_RESET_PIN,PI_OUTPUT);
	gpio_write(pi,MULTOS_RESET_PIN, 1);
	sleep(1);

	// Connect to I2C device
	i2cFd = i2c_open(pi,1,MULTOS_SLAVE_DEVICE,0);

	if(i2cFd < 0)
		return (1);
#endif

	reset();

	traceMessage("Device ready.");

	// Flag that setup has completed OK.
	sharedMem->status = AVAILABLE;

	// Message handling loop
	while(1)
	{
		if(trace == 2 && lastStatus != sharedMem->status)
		{
			sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
			traceMessage(msgBuf);
		}

		// Reset if previously in error condition
		if(inErrorState)
		{
			sharedMem->status = OFFLINE;
			sharedMem->connectedPid = 0;
			connectedPid = 0;
			if(trace == 2 && lastStatus != sharedMem->status)
			{
				sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
				traceMessage(msgBuf);
			}
			if(reset())
			{
				inErrorState = 0;
				sharedMem->status = AVAILABLE;
			}
			else
				sleep(1);
		}

		// If a client is preparing to communicate
		else if(sharedMem->status == REQUESTED && connectedPid == 0)
		{
			sharedMem->connectedPid = sharedMem->requestingPid;
			connectedPid = sharedMem->connectedPid;
			sharedMem->status = CONNECTED;
			if(trace == 2 && lastStatus != sharedMem->status)
			{
				sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
				traceMessage(msgBuf);
			}
			// Cut the delay time so as to react quickly
			delay = SHORT_DELAY;
		}
		// If a client wants to disconnect
		else if(sharedMem->status == DISCONNECT && connectedPid == sharedMem->requestingPid)
		{
			connectedPid = 0;
			sharedMem->connectedPid = 0;
			sharedMem->status = AVAILABLE;
		}
		// If no client communicating
		else if(sharedMem->status == AVAILABLE)
		{
			// Long delay as no active client
			delay = LONG_DELAY;
			connectedPid = 0;
			sharedMem->connectedPid = 0;
		}
		// If client is requesting a reset
		else if(sharedMem->status == CMD_READY && sharedMem->CLA == 0xBE && sharedMem->INS == 0xFF)
		{
			// Make sure another process hasn't managed to overlap (can happen with frequent calls from two clients)
			if(connectedPid == sharedMem->requestingPid)
			{
				sharedMem->status = CMD_PROCESSING;
				if(trace == 2 && lastStatus != sharedMem->status)
				{
					sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
					traceMessage(msgBuf);
				}

				// Do the reset
				sharedMem->La = 0;
				if(reset())
					sharedMem->SW12 = 0x9000;
				else
					sharedMem->SW12 = 0xFFFF;

				sharedMem->status = RESULT_AVAILABLE;
				if(trace == 2 && lastStatus != sharedMem->status)
				{
					sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
					traceMessage(msgBuf);
				}
				delay = LONG_DELAY;
			}
		}
		// If a client wants a command processing
		else if(sharedMem->status == CMD_READY)
		{
			// Make sure another process hasn't managed to overlap (can happen with frequent calls from two clients)
			if(connectedPid == sharedMem->requestingPid)
			{
				sharedMem->status = CMD_PROCESSING;
				if(trace == 2 && lastStatus != sharedMem->status)
				{
					sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
					traceMessage(msgBuf);
				}
				offset = 0;
				buffer[offset] = 128; // 80hex
				offset = offset + 3; // Length to be inserted later
				buffer[offset] = sharedMem->CLA;
				offset = offset + 1;
				buffer[offset] = sharedMem->INS;
				offset = offset + 1;
				buffer[offset] = sharedMem->P1;
				offset = offset + 1;
				buffer[offset] = sharedMem->P2;
				offset = offset + 1;

				if (sharedMem->Lc == 0) // Lc not set, Le could be set or be zero
				{
					buffer[offset] = sharedMem->Le / 256;
					offset = offset + 1;
					buffer[offset] = sharedMem->Le % 256;
					offset = offset + 1;
				}
				else // Lc set, Le may be set
				{
					buffer[offset] = sharedMem->Lc / 256;
					offset = offset + 1;
					buffer[offset] = sharedMem->Lc % 256;
					offset = offset + 1;
					if (sharedMem->Lc > 0)
					{
						memcpy(buffer+offset,sharedMem->data,sharedMem->Lc);
						offset = offset + sharedMem->Lc;
						if (sharedMem->Le > 0 || sharedMem->case4)
						{
							buffer[offset] = sharedMem->Le / 256;
							offset = offset + 1;
							buffer[offset] = sharedMem->Le % 256;
							offset = offset + 1;
						}
					}
				}
				// Set length of data
				sendLen = offset;
				offset = offset - 3;
				buffer[1] = offset / 256;
				buffer[2] = offset % 256;

				utilBinToHex(buffer,hex,9);
				if(trace)
				{
					sprintf(msgBuf,"Processing command %s for PID %ld",hex+6,connectedPid);
					traceMessage(msgBuf);
				}

				// Send command - wait for it to get there
				sendAPDUOverI2C(buffer,sendLen);

				// Read reply
				memset(buffer,0,sizeof(buffer));
				nTotal = readI2CReply(buffer,sizeof(buffer),sharedMem->timeout);
				if(nTotal == 0 || nTotal < 5)
				{
					sharedMem->status = ERROR;
					inErrorState = 1;
				}
				else
				{
					// Set up output in shared memory
					sharedMem->La = nTotal - 5;
					sharedMem->SW12 = buffer[nTotal-2] * 256 + buffer[nTotal-1];
					memcpy(sharedMem->data,buffer+3,nTotal - 5);
					//utilBinToHex(buffer,hex,nTotal);
					if(trace)
					{
						if(nTotal >= 2)
						{
							utilBinToHex(buffer+nTotal-2,hex,2);
							sprintf(msgBuf,"SW12: %s",hex);
							traceMessage(msgBuf);
						}
						sprintf(msgBuf,"Result bytes available: %d",nTotal-5);
						traceMessage(msgBuf);
						utilBinToHex(buffer+3,hex,nTotal-5);
						traceMessage(hex);
					}
					sharedMem->status = RESULT_AVAILABLE;
					if(trace == 2 && lastStatus != sharedMem->status)
					{
						sprintf(msgBuf,"State:%d RequesterPid:%ld ConnectedPid:%ld",sharedMem->status, sharedMem->requestingPid, sharedMem->connectedPid);
						traceMessage(msgBuf);
					}
					delay = LONG_DELAY;
				}
			}
		}

		usleep(delay);

		// Clients have to act or lose connection. Prevents blocking.
		if (sharedMem->status != AVAILABLE && sharedMem->status != ERROR)
		{
			if(clientTimeOut < delay)
			{
				// Make available again
				connectedPid = 0;
				sharedMem->connectedPid = 0;
				sharedMem->status = AVAILABLE;
				clientTimeOut = CLIENT_TIMEOUT;

				if(trace)
					traceMessage("Connection timed out.");
			}
			else
				clientTimeOut -= delay;
		}

		lastStatus = sharedMem->status;
	}
	return(0);
}
