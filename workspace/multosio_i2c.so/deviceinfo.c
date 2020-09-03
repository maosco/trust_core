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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "multosio.h"
#define APDU_TIMEOUT 1000

void multosGetChipInfo(unsigned char requestByte, multosChipData_t *data)
{
	unsigned short La;
	unsigned char appNum;
	unsigned char buff[255];
	unsigned short sw;
	data->validFields = 0;
	data->mkdPkCLen = 0;
	data->numApps = 0;

	if(requestByte & MCDNO_VALID)
	{
		sw = multosSendAPDU(0x80,0,0,0,0,0x7F,&La,0,buff,sizeof(buff),APDU_TIMEOUT);
		if(sw == 0x9000)
		{
			memcpy(data->mcdNumber,buff+16,8);
			data->validFields += MCDNO_VALID;
		}
	}
	if(requestByte & MKDPKC_VALID)
	{
		sw = multosSendAPDU(0x80,0x10,7,0,0,0,&La,0,buff,sizeof(buff),APDU_TIMEOUT);
		if(sw == 0x9000)
		{
			memcpy(data->mkdPkC,buff,La <= MULTOS_MAX_PKC_LEN ? La : MULTOS_MAX_PKC_LEN);
			data->mkdPkCLen = La;
			data->validFields += MKDPKC_VALID;
		}
	}
	if(requestByte & REMAIN_E2_VALID)
	{
		sw = multosSendAPDU(0x80,0x10,1,0,0,3,&La,0,buff,sizeof(buff),APDU_TIMEOUT);
		if(sw == 0x9000)
		{
			data->remainingE2size = buff[0] * 65536 + buff[1] * 256 + buff[2];
			data->validFields += REMAIN_E2_VALID;
		}
	}
	if(requestByte & APPDATA_VALID)
	{
		sw = multosSendAPDU(0x80,0x10,0x06,0,0,0,&La,1,buff,sizeof(buff),APDU_TIMEOUT);
		if(sw == 0x9000)
		{
			data->numApps = La / 20;
			if(data->numApps > MULTOS_MAX_APPS)
				data->numApps = MULTOS_MAX_APPS;
			for(appNum = 0; appNum < data->numApps;appNum++)
			{
				data->apps[appNum].aidLen = buff[appNum*20];
				memcpy(data->apps[appNum].aid,buff+(appNum*20+1),16);
				data->apps[appNum].appSize = (buff[appNum*20 + 17] * 65536) + (buff[appNum*20 + 18] * 256)+ buff[appNum*20 + 19];
			}
			data->validFields += APPDATA_VALID;
		}
	}
	if(requestByte & BUILDNO_VALID)
	{
		sw = multosSendAPDU(0x80,0x10,0x0A,0,0,0,&La,1,buff,sizeof(buff),APDU_TIMEOUT);
		if(sw == 0x9000)
		{
			if(La > 4)
				La = 4;
			memcpy(data->buildNumber,buff,La <= MULTOS_MAX_BUILDNUM_LEN ? La : MULTOS_MAX_BUILDNUM_LEN);
			data->validFields += BUILDNO_VALID;
		}
	}
}

void multosHALInfo(char *desc, unsigned char *major, unsigned char *minor)
{
	strcpy(desc,MULTOSIO_VERSION_DESC);
	*major = MULTOSIO_VERSION_MAJOR;
	*minor = MULTOSIO_VERSION_MINOR;
}
