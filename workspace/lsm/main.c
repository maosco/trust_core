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
 ** List the contents of the currently connected MULTOS device.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <multosio.h>


int main(int argc, char *argv[])
{
	multosChipData_t deviceData;
	int n,m, l;
	char spaces[32];
	char aidHex[33];

	// Setup up MULTOS device
	if(!multosInit())
	{
		printf("Failed to initialise MULTOS device\n");
		return(1);
	}

	if(!multosReset())
	{
		printf("Failed to reset MULTOS device\n");
		return(1);
	}

	// Request just the list of loaded applications
	multosGetChipInfo(APPDATA_VALID,&deviceData);

	// If OK
	if(deviceData.validFields & APPDATA_VALID)
	{
		if(deviceData.numApps == 0)
			printf("No applications loaded.\n");
		else
		{
			// Print header
			printf("\n");
			printf("AID                              Size(bytes)\n");
			printf("--------------------------------------------\n");
			fflush(stdout);
			// Print details for each app.
			for(n = 0; n < deviceData.numApps; n++)
			{
				// Convert AID to Ascii Hex
				l = deviceData.apps[n].aidLen;
				multosBinToHex(deviceData.apps[n].aid,aidHex,l);

				// Calculate padding
				for(m = 0; m < 32 -(l*2) ;m++)
					spaces[m] = ' ';
				spaces[m] = '\0';
				printf("%s%s %ld\n",aidHex,spaces,deviceData.apps[n].appSize);

			}
		}
	}
	else
	{
		printf("Failed to read MULTOS device.\n");
		return(1);
	}

	printf("\n");
	return(0);
}
