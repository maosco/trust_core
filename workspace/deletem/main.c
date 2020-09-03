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

/*
 * Command line application to delete a MULTOS application using the correct ADC file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <multosio.h>

int main(int argc, char *argv[])
{
	char error[128];

	if(argc != 2)
	{
		printf("Usage: deletem adcfile\n");
		return(1);
	}

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

	if(multosDeleteApp(argv[1],error,sizeof(error)))
	{
		printf("Deleted OK\n");
		return(0);
	}

	// Failed to load
	printf("Delete failed: %s\n",error);
	return(1);
}


