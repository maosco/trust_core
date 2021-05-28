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



static	char acTable[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
	                                '4', '5', '6', '7', '8', '9', '+', '/'};

static int numPad[] = {0, 2, 1};

void base64Encode(unsigned char *pData,
                    unsigned short wInputLen,
					unsigned short *pwOutputLen,
                    char *pEncodedData)
{

	int i,j,k,inThrees;
	unsigned long dwA, dwB, dwC, dwTriple;

    *pwOutputLen = ((wInputLen - 1) / 3) * 4 + 4;

    // Process full groups of three first - can do the octet_x part more simply
    inThrees = (wInputLen / 3) * 3;
    i = 0;
    j = 0;
    k = 0;

    while (i < inThrees) {

        dwA = pData[i++];
        dwB = pData[i++];
        dwC = pData[i++];

        dwTriple = (dwA << 0x10) + (dwB << 0x08) + dwC;

        pEncodedData[j++] = acTable[(dwTriple >> 3 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 2 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 1 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 0 * 6) & 0x3F];
        k += 4;
    }

    // Process remainder
    while (i < wInputLen)
    {
        dwA = i < wInputLen ? (unsigned char)pData[i++] : 0;
        dwB = i < wInputLen ? (unsigned char)pData[i++] : 0;
        dwC = i < wInputLen ? (unsigned char)pData[i++] : 0;

        dwTriple = (dwA << 0x10) + (dwB << 0x08) + dwC;

        pEncodedData[j++] = acTable[(dwTriple >> 3 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 2 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 1 * 6) & 0x3F];
        pEncodedData[j++] = acTable[(dwTriple >> 0 * 6) & 0x3F];
        k += 4;
    }

    // Pad
    for (i = 0; i < numPad[wInputLen % 3]; i++)
        pEncodedData[*pwOutputLen - 1 - i] = '=';
}
