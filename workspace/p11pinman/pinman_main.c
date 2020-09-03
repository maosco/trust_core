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
#include <multosio.h>
#include <ncurses.h>
#include <tc_api.h>

typedef unsigned short WORD;

void enterPIN(CK_BYTE_PTR pPIN, CK_ULONG wLen, char *sPrompt)
{
	int i;
	unsigned char ch;

	memset(pPIN,0xFF,wLen);
	initscr();
	printw(sPrompt);
	printw("\n");
	noecho();
	i = 0;
	do
	{
		ch = getch();
		if(ch != 10) // Return
		{
			printw("*");
			pPIN[i] = ch;
			i++;
		}
	}
	while(ch != 10 && i < wLen);
	echo();
	printw("\n");
	endwin();
}

void printUsage(void)
{
	printf("USAGE: p11pinman [-v] [user|keyman|so]\n");
	printf("  Change a PIN and reset the retry counter.\n");
}

int main(int argc, char *argv[])
{
	CK_BYTE soPIN[TC_PIN_SIZE];
	CK_BYTE newPIN[TC_PIN_SIZE];
	CK_BYTE newPINCheck[TC_PIN_SIZE];
	CK_BYTE user;
	char message[128];
	int remainingTries;

	if(argc != 2 || (strcmp(argv[1],"user") != 0 && strcmp(argv[1],"keyman") != 0 && strcmp(argv[1],"so") != 0 && strcmp(argv[1],"-v") != 0) )
	{
		printUsage();
		return 0;
	}

	if(strcmp(argv[1],"user") == 0)
		user = TC_PINREF_G;
	else if(strcmp(argv[1],"keyman") == 0)
		user = TC_PINREF_K;
	else if(strcmp(argv[1],"so") == 0)
		user = TC_PINREF_SO;
	else if (strcmp(argv[1],"-v") == 0)
	{
		printf("Version 0.1\n");
		return 0;
	}

	// Make sure the chip is ready to use
	multosReset();
	tcSelectApp();

	// Verify the SO pin
	enterPIN(soPIN,TC_PIN_SIZE,"Enter SO PIN");

	// Enter the new PIN twice
	sprintf(message,"Enter new %s PIN",argv[1]);
	enterPIN(newPIN,TC_PIN_SIZE,message);

	sprintf(message,"Re-enter new %s PIN",argv[1]);
	enterPIN(newPINCheck,TC_PIN_SIZE,message);

	// Compare values
	if(memcmp(newPIN,newPINCheck,TC_PIN_SIZE) == 0)
	{
		if(tcChangePIN(user,soPIN, newPIN))
			printf("PIN changed OK\n");
		else
			printf("ERROR: PIN change FAILED\n");
	}
	else
		printf("ERROR: Values did not match\n");
	memset(newPIN,0,TC_PIN_SIZE);
	memset(newPINCheck,0,TC_PIN_SIZE);

	remainingTries = tcVerifyPIN2(TC_PINREF_SO,NULL);
	printf("Security Officer PIN: %d tries remaining.\n",remainingTries);

	// Reset chip to force logouts
	multosReset();

	return 0;
}


