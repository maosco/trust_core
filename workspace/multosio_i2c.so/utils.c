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

#include <string.h>

static char nibbleToHexChar(int nibble)
{
	char result = '?';
	switch(nibble)
	{
		case 0: result = '0'; break;
		case 1: result = '1'; break;
		case 2: result = '2'; break;
		case 3: result = '3'; break;
		case 4: result = '4'; break;
		case 5: result = '5'; break;
		case 6: result = '6'; break;
		case 7: result = '7'; break;
		case 8: result = '8'; break;
		case 9: result = '9'; break;
		case 10: result = 'A'; break;
		case 11: result = 'B'; break;
		case 12: result = 'C'; break;
		case 13: result = 'D'; break;
		case 14: result = 'E'; break;
		case 15: result = 'F'; break;
		default: result = '?'; break;
	}
	return(result);
}

static unsigned char hexCharToNibble(char hex)
{
	if(hex >= (char)'0' && hex <= (char)'9')
		return(hex - '0');
	return(hex - 'A' + 10);
}

void multosBinToHex(unsigned char* binIn, char* hexOut, int len)
{
	int x;
	int hi,lo;
	char hichar,lochar;

	memset(hexOut,0,len*2+1);

	for(x=0;x < len;x++)
	{
		// Split input byte into two nibbles
		hi = binIn[x] >> 4;
		lo = binIn[x] & 0x0F;

		// Convert to hex characters
		hichar = nibbleToHexChar(hi);
		lochar = nibbleToHexChar(lo);

		// Add to output buffer
		hexOut[x*2] = hichar;
		hexOut[(x*2)+1] = lochar;
	}
}

void multosHexToBin(char *hexIn, unsigned char *binOut, int len)
{
	unsigned char b;
	char lo,hi;

	for(b=0; b<len; b++)
	{
		hi = hexIn[b*2];
		lo = hexIn[(b*2)+1];
		binOut[b] = (hexCharToNibble(hi) * 16) + hexCharToNibble(lo);
	}
}

// Convert little endian word to big endian hex
void multosWordToHex(unsigned short w, char* hexOut)
{
	unsigned char bin[2];
	bin[0] = w / 256;
	bin[1] = w;
	multosBinToHex(bin,hexOut,2);
}
