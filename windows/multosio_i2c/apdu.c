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

#include "platform.h"

extern void multosHexToBin(char *hexIn, unsigned char *binOut, int len);


// This buffer holds the correctly formatted APDU to be sent and the reply.
// This size is set to the public memory size in the M5-P22 chip.
#define PUB_SIZE 3000
static unsigned char abBuffer[PUB_SIZE];

// Definitions of the MULTOS Command Mode I2C registers
#define MULTOS_TAGLEN_REG       0
#define MULTOS_VALUE_REG        1
#define MULTOS_RESPONSE_TAG_REG 0x80
#define MULTOS_RESPONSE_TAG_LEN 0x81
#define MULTOS_RESPONSE_TAG_VAL 0x82
#define MULTOS_MASTER_I2C_BUFSIZE_REG 0x83

#define MULTOS_TAGLEN_REG_LEN   3 // Tag(1) + Len(2)


// ------------------------------ I2C support functions ----------------------------
// Take an APDU formatted in the MULTOS Command Mode format and send it over
// the i2c interface, in blocks as needed
static void sendAPDUOverI2C(unsigned char *buff, int toSend)
{
  unsigned char i2cbuff[MASTER_I2C_BUF_SIZE];
  int maxDataPerBlock = MASTER_I2C_BUF_SIZE - 4;
  int numBlocks,remain,dataLen;
  int b;

  // Send the TAG and LENGTH from the incoming buffer to appropriate register of the MULTOS i2c interface
  i2cbuff[0] = 0x55; // USB-ISS command byte
  i2cbuff[1] = 0xBE; // MULTOS I2C write address
  i2cbuff[2] = MULTOS_TAGLEN_REG;
  i2cbuff[3] = MULTOS_TAGLEN_REG_LEN;
  memcpy(i2cbuff+4,buff,MULTOS_TAGLEN_REG_LEN);
  writeToI2C(i2cbuff,MULTOS_TAGLEN_REG_LEN+4,TRUE);

  // Send the command DATA to register 1, in chunks as needed
  if(toSend > MULTOS_TAGLEN_REG_LEN)
  {
    dataLen = toSend - MULTOS_TAGLEN_REG_LEN;
    i2cbuff[2] = MULTOS_VALUE_REG; // Change to the value register
    numBlocks = dataLen / maxDataPerBlock;
    remain = dataLen % maxDataPerBlock;
    for(b=0;b<numBlocks;b++)
    {
	  i2cbuff[3] = maxDataPerBlock;
      memcpy(i2cbuff+4,buff+MULTOS_TAGLEN_REG_LEN+(b*maxDataPerBlock),maxDataPerBlock);
      writeToI2C(i2cbuff,maxDataPerBlock+4,TRUE);
    }
    if(remain)
    {
	  i2cbuff[3] = remain;
      memcpy(i2cbuff+4,buff+MULTOS_TAGLEN_REG_LEN+(numBlocks*maxDataPerBlock),remain);
      writeToI2C(i2cbuff,remain+4,TRUE);
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
  int numBlocks,remain,responseLength;

  // First request the tag from MULTOS
  i2cbuff[0] = 0x55; // USB-ISS command
  i2cbuff[1] = 0xBF; // Read version of MULTOS i2c address
  i2cbuff[2] = MULTOS_RESPONSE_TAG_REG; // Register containing tag
  i2cbuff[3] = 1; // Number of bytes to read
  writeToI2C(i2cbuff,4,FALSE);
  nActual = readI2C(buff,1,maxWait);

  if(nActual > 0)
	  nread += nActual;

  if(nActual > 0 && buff[0] > 0x3F && buff[0] <= 0xBF)
  {
    // Request length from length register
    unsigned char lengthLength = 2;
    if(buff[0] < 0x80)
      lengthLength = 1;

    i2cbuff[2] = MULTOS_RESPONSE_TAG_LEN; // Register containing length
	i2cbuff[3] = lengthLength;
    writeToI2C(i2cbuff,4,FALSE);
    nActual = readI2C(buff+nread,lengthLength,maxWait);
    nread += nActual;

    // Calculate the length of the response data
    responseLength = buff[1];
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
    numBlocks = responseLength / MASTER_I2C_BUF_SIZE;
    remain = responseLength % MASTER_I2C_BUF_SIZE;
    i2cbuff[2] = MULTOS_RESPONSE_TAG_VAL; // Register containing response
    for(b = 0; b < numBlocks; b++)
    {
	  i2cbuff[3] = MASTER_I2C_BUF_SIZE;
      writeToI2C(i2cbuff,4,FALSE); // Read the response
      nActual = readI2C(buff+nread,MASTER_I2C_BUF_SIZE,maxWait);
      nread += nActual;
    }
    if(remain)
    {
	  i2cbuff[3] = remain;
      writeToI2C(i2cbuff,4,FALSE);
      nActual = readI2C(buff+nread,remain,maxWait);
      nread += nActual;
    }
  }

  return nread;
}


// ------------------------------ Exported functions ----------------------------
unsigned short multosSendAPDU(unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned short Lc, unsigned short Le, unsigned short *La, unsigned char case4, unsigned char *data, int dataBuffLen, unsigned long maxWait)
{
	  unsigned short wSW12;
	  unsigned short wI;
	  unsigned short wRxCount;
	  unsigned short wSendLength;

#ifdef PRINT_APDU
	  unsigned short i;
	  FILE *fp;
#ifdef _WIN32
	  fp = fopen("c:\\temp\\apdulog.txt","a");
#else
	  fp = fopen("/home/pi/apdulog.txt","a");
#endif
	  fprintf(fp,"%02x %02x %02x %02x %04x %04x ",CLA,INS,P1,P2,Lc,Le);
	  fflush(fp);
#endif

	  if(serialStream == INVALID_HANDLE_VALUE)
		  multosInit();

	  if(serialStream == INVALID_HANDLE_VALUE)
	  {
#ifdef PRINT_APDU
		  fprintf(fp,"=> 0000 FFFF\n");
		  fclose(fp);
#endif
		  *La = 0;
		  return (0xFFFF);
	  }

	  // abBuffer will contain the formatted message to send over i2c
	  wI = 0;
	  abBuffer[0] = 0x80; // The "APDU Command" tag
	  // Two byte space left for the length bytes - fill in later

	  // Fill in the APDU header
	  abBuffer[3] = CLA;
	  abBuffer[4] = INS;
	  abBuffer[5] = P1;
	  abBuffer[6] = P2;
	  wI = 7;

	  if (Lc == 0) // Lc not set, Le could be set or be zero
	  {
	      abBuffer[wI] = Le / 256;
	      abBuffer[wI + 1] = Le % 256;
	      wI += 2;
	  }
	  else
	  {
	    // Lc set, Le may be set
	    abBuffer[wI] = Lc / 256;
	    abBuffer[wI + 1] = Lc % 256;
	    wI += 2;
#ifdef PRINT_APDU
	    // Print out the data
	    for(i=0;i<Lc;i++)
	    	fprintf(fp,"%02x ",data[i]);
	    fflush(fp);
#endif
	    // Copy in the APDU data
	    memcpy(abBuffer + wI, data, Lc);
	    wI += Lc;

	    // Append Le if needed
	    if (Le > 0 || case4)
	    {
	      abBuffer[wI] = Le / 256;
	      abBuffer[wI + 1] = Le % 256;
	      wI += 2;
	    }
	  }

	  // Set length of data
	  wSendLength = wI;
	  wI -= 3;
	  abBuffer[1] = wI / 256;
	  abBuffer[2] = wI % 256;

	  // Send command
	  sendAPDUOverI2C(abBuffer,wSendLength);

	  // Read reply
	  memset(abBuffer, 0, sizeof(abBuffer));
	  wRxCount = readI2CReply(abBuffer, sizeof(abBuffer), maxWait);
	  //printf("%d bytes in reply\n",wRxCount);
	  if(wRxCount == 0)
	  {
#ifdef PRINT_APDU
		  fprintf(fp,"=> 0000 0000\n");
		  fclose(fp);
#endif
		  *La = 0;
		  return (0x0000);
	  }
	  // Return status always the last two bytes returned
	  wSW12 = (abBuffer[wRxCount - 2] * 256) + abBuffer[wRxCount - 1];

	  // Set up data to return
	  *La = wRxCount - 5;  // serial protocol header + SW12 = 5 unsigned chars
	  if(*La > dataBuffLen)
		  *La = dataBuffLen; // Prevent overflows.
	  if(*La > 0)
	    memcpy(data,abBuffer+3,*La);
#ifdef PRINT_APDU
	  fprintf(fp,"=> %04x %04x\n",*La,wSW12);
	  fclose(fp);
#endif
	  return (wSW12);
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


