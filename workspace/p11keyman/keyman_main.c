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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <multosio.h>
#include <tc_api.h>
#ifdef _WIN32
#include<conio.h>
#else
#include <ncurses.h>
#endif
#include <ctype.h>

typedef unsigned short WORD;

char sAESKey[] = "AES";
char sMSKey[] = "MS ";
char sPMSKey[] = "PMS";
char sTLSKey[] = "TLS";

#ifdef _WIN32
int enterSecret(CK_BYTE_PTR pData, CK_ULONG wLen, char *sPrompt)
{
	int i;
	CK_BYTE b;

    printf("%s\n",sPrompt);

    for(i=0; i<wLen;i++)
	{
        b = _getch();
        printf("*");

		// Stop if enter key pressed
        if(b == '\r')
            break;
		else
			pData[i] = b;

		// If backspace pressed
        if(pData[i] == '\b')
		{
            if(i == 0)                
				printf("\b \b");	
            else if (i >= 1)
			{
                pData[i-1] = '\0';
                i = i - 2;                
				printf("\b \b\b \b");
            }
         }
    }
	printf("\n");
	return i;
}
#else
void enterSecret(CK_BYTE_PTR pData, CK_ULONG wLen, char *sPrompt)
{
	int i;
	unsigned char ch;

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
			pData[i] = ch;
			i++;
		}
	}
	while(ch != 10 && i < wLen);
	echo();
	printw("\n");
	endwin();
}
#endif

void enterPIN(CK_BYTE_PTR pPIN, CK_ULONG wLen, char *sPrompt)
{
	memset(pPIN,0xFF,wLen);
	enterSecret(pPIN,wLen,sPrompt);
}

void setFlags(WORD wAttrs,char *pFlags)
{
	if((wAttrs & TC_ATTR_ENCRYPT) == TC_ATTR_ENCRYPT)
		pFlags[0] = 'E';
	else
		pFlags[0] = ' ';

	if((wAttrs & TC_ATTR_DECRYPT) == TC_ATTR_DECRYPT)
		pFlags[1] = 'D';
	else
		pFlags[1] = ' ';

	if((wAttrs & TC_ATTR_WRAP) == TC_ATTR_WRAP)
		pFlags[2] = 'W';
	else
		pFlags[2] = ' ';

	if((wAttrs & TC_ATTR_UNWRAP) == TC_ATTR_UNWRAP)
		pFlags[3] = 'U';
	else
		pFlags[3] = ' ';

	if((wAttrs & TC_ATTR_EXTRACT) == TC_ATTR_EXTRACT)
		pFlags[4] = 'X';
	else
		pFlags[4] = ' ';

	pFlags[5] = 0;
}

WORD parseFlags(char *s)
{
	int i;
	WORD wAttrs = 0;

	for(i=0;i<strlen(s);i++)
	{
		switch(s[i])
		{
			case 'E': wAttrs += TC_ATTR_ENCRYPT;break;
			case 'D': wAttrs += TC_ATTR_DECRYPT;break;
			case 'W': wAttrs += TC_ATTR_WRAP;break;
			case 'U': wAttrs += TC_ATTR_UNWRAP;break;
			case 'X': wAttrs += TC_ATTR_EXTRACT;break;
			default: printf("Ignoring bad permission flag %c\n",s[i]);
		}
	}
	return wAttrs;
}

void parseLabel(char *s, BYTE *pLabel)
{
	memset(pLabel,0,TC_SECRET_KEY_LABEL_LEN+1);
	strncpy((char*)pLabel,s,TC_SECRET_KEY_LABEL_LEN);
}

void parseHex(char *s, BYTE *abBinary, int nBytes)
{
	int i;

	memset(abBinary,0,nBytes);

	// Put alleged hex into upper case and check only valid characters are supplied
	for(i=0;i<nBytes*2;i++)
	{
		s[i] = toupper(s[i]);
		if(! ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F')) )
		{
			printf("Invalid hex characters in input\n");
			return;
		}
	}

	// Finally convert
	multosHexToBin(s,abBinary,nBytes);
}

int validateNumber(char *s)
{
	int i;

	for(i=0;i<strlen(s);i++)
	{
		if (!isdigit(s[i]))
		{
			printf("Invalid key number\n");
			return -1;
		}
	}
	return atoi(s);
}

void printUsage(void)
{
	printf("USAGE: p11keyman [Options]\n");
	printf("  Manage Symmetric Keys.\n");
	printf("  Options:\n");
	printf("    -d N                  Delete key N.\n");
	printf("    -D                    Delete all keys.\n");
	printf("    -g L FLAGS LABEL      Generate key (L bytes long) with permissions\n");
	printf("                          set in FLAGS and the label LABEL.\n");
	printf("    -i L FLAGS LABEL      Import key (L bytes long) from clear components, with permissions\n");
	printf("                          set in FLAGS, and the label LABEL.\n");
	printf("    -l                    List keys.\n");
	printf("    -u L FLAGS LABEL N V K  Unwrap and import encrypted key (L bytes long) value V(hex) with KCV K(hex) using key N\n");
	printf("                          with permissions set in FLAGS and the label LABEL.\n");
	printf("    -w M N                Wrap and export key M using key N.\n");
	printf("    -v                    Print application version.\n");
	printf("\n");
	printf("  FLAGS:\n");
	printf("    E             Encrypt permission.\n");
	printf("    D             Decrypt permission.\n");
	printf("    W             Key wrap permission.\n");
	printf("    U             Key unwrap permission.\n");
	printf("    X             Extractable permission.\n");
	printf("\n");
	printf("  Examples:\n");
	printf("      p11keyman -g 16 EX ENC-4752-001\n");
	printf("      p11keyman -i 16 EX ENC-4752-002\n");
	printf("      p11keyman -u 16 E DEC-1234-001 2 01020304050607080102030405060708 A1B1C1\n");
}

int main(int argc, char *argv[])
{
	TC_SECRET_KEY_ATTRS attrs;
	int i;
	int keyToExport;
	char *pKeyType;
	char sFlags[6];
	BYTE abPIN[TC_PIN_SIZE];
	BYTE abPINConf[TC_PIN_SIZE];
	WORD wFlags;
	int keyLen;
	CK_OBJECT_HANDLE handle;
	BYTE abLabel[TC_SECRET_KEY_LABEL_LEN+1];
	BYTE abComp1[32]; // Size == max AES key size
	BYTE abComp2[32];
	BYTE abComp3[32];
	BYTE abComponentString[64];
	BYTE abKcv[3];

	if( (argc == 2 && strcmp(argv[1],"-l") != 0 && strcmp(argv[1],"-D") != 0 && strcmp(argv[1],"-v") != 0) ||
		(argc == 3 && strcmp(argv[1],"-d") != 0 ) ||
		(argc == 4 && strcmp(argv[1],"-w") != 0 ) ||
		(argc == 5 && strcmp(argv[1],"-g") != 0 && strcmp(argv[1],"-i") != 0 ) ||
		(argc == 8 && strcmp(argv[1],"-u") != 0 ) ||
		argc == 1)
	{
		printUsage();
		return 0;
	}


	// Version requires no chip access
	if(strcmp(argv[1],"-v") == 0)
	{
		printf("Version: 0.1\n");
		return 0;
	}

	// Make sure the chip is ready to use
#ifdef _WIN32
	multosInit();
#endif
	multosReset();
	tcSelectApp();

	// *************** List Keys - PIN not required ********************************************
	if(strcmp(argv[1],"-l") == 0)
	{
		printf("\n");
		printf("Index Label                        KCV    Type Flags\n");
		printf("----------------------------------------------------\n");
		for(i = 0;i<TC_NUM_SECRET_KEYS;i++)
		{
			if(tcReadSecretKeyAttrs(TC_EFTYPE_SECRET+i,&attrs))
			{
				switch(attrs.bKeyType) {
					case TC_KEYTYPE_AES: pKeyType = sAESKey; break;
					case TC_KEYTYPE_MS: pKeyType = sMSKey; break;
					case TC_KEYTYPE_PMS: pKeyType = sPMSKey; break;
					case TC_TLS_KEYSET: pKeyType = sTLSKey; break;
					default: pKeyType = NULL;
				}
				setFlags(attrs.wAttrs,sFlags);
				printf("%d     %-28s %02x%02x%02x %s  %s\n",i,attrs.acLabel,attrs.abKcv[0],attrs.abKcv[1],attrs.abKcv[2],pKeyType,sFlags);
			}
		}
	}
	else
	{
		// ********* Remaining functions need the PIN ************************
		enterPIN(abPIN,TC_PIN_SIZE,"Enter key management PIN");
		// Note that the PIN is only verified in the chip at the last possible moment. This is to
		// try and avoid leaving the chip authorised if the user forces a quit of this program.

		// ****************** Delete all keys ********************************
		if (strcmp(argv[1],"-D") == 0)
		{
			// Enter PIN a second time to confirm
			enterPIN(abPINConf,TC_PIN_SIZE,"Delete all keys? Enter PIN again to confirm.");
			if(memcmp(abPIN,abPINConf,TC_PIN_SIZE) == 0)
			{
				if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
				{
					printf("PIN invalid\n");
					multosReset();
					return 0;
				}

				// Delete all keys
				for(i = 0;i<TC_NUM_SECRET_KEYS;i++)
				{
					if(tcDeleteFile(TC_EFTYPE_SECRET+i))
						printf("Deleted %d\n",i);
				}
			}
			else
				printf("Cancelled.\n");
		}
		// ***************** Delete one key ***********************************
		else if (strcmp(argv[1],"-d") == 0)
		{
			if( (i = validateNumber(argv[2])) >= 0)
			{
				if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
				{
					printf("PIN invalid\n");
					multosReset();
					return 0;
				}

				if(tcDeleteFile(TC_EFTYPE_SECRET+i))
					printf("Deleted %d\n",i);
				else
					printf("Failed to delete key %d\n",i);					if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
					{
						printf("PIN invalid\n");
						multosReset();
						return 0;
					}
			}
		}
		// ************** Generate a key **************************************
		else if (strcmp(argv[1],"-g") == 0)
		{
			keyLen = validateNumber(argv[2]);
			if(keyLen == 16 || keyLen == 24 || keyLen == 32)
			{
				wFlags = parseFlags(argv[3]);
				parseLabel(argv[4],abLabel);

				if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
				{
					printf("PIN invalid\n");
					multosReset();
					return 0;
				}

				if(tcGenerateAesKey(abLabel,keyLen,wFlags,&handle))
					printf("Key generated OK\n");
				else
					printf("Key generation failed\n");
			}
			else
				printf("Invalid key length %s\n",argv[2]);
		}
		// ************** Import a clear key from components **************************************
		else if (strcmp(argv[1],"-i") == 0)
		{
			keyLen = validateNumber(argv[2]);
			if(keyLen == 16 || keyLen == 24 || keyLen == 32)
			{
				wFlags = parseFlags(argv[3]);
				parseLabel(argv[4],abLabel);

				// Get the clear components
				enterSecret(abComponentString,keyLen*2,"Enter component 1");
				parseHex((char*)abComponentString,abComp1,keyLen);
				enterSecret(abComponentString,keyLen*2,"Enter component 2");
				parseHex((char*)abComponentString,abComp2,keyLen);
				enterSecret(abComponentString,keyLen*2,"Enter component 3");
				parseHex((char*)abComponentString,abComp3,keyLen);

				// Combine
				for(i=0;i<keyLen;i++)
					abComp1[i] = abComp1[i] ^ abComp2[i] ^ abComp3[i];

				if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
				{
					printf("PIN invalid\n");
					multosReset();
					return 0;
				}

				if(tcImportAesKey(abLabel,keyLen,wFlags,abComp1,&handle))
					printf("Key imported OK\n");
				else
					printf("Key import failed\n");
			}
			else
				printf("Invalid key length %s\n",argv[2]);
		}
		// ************** Wrap one key with another **************************************
		else if (strcmp(argv[1],"-w") == 0)
		{
			if((i = validateNumber(argv[3])) >= 0)
			{
				if((keyToExport = validateNumber(argv[2])) >= 0)
				{
					tcMseSetAlgo(TC_ALGO_AES_CBC,TC_TEMPLATE_CONFIDENTIALITY);
					tcMseSetKeyFile(TC_EFTYPE_SECRET+i,TC_TEMPLATE_CONFIDENTIALITY);
					if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
					{
						printf("PIN invalid\n");
						multosReset();
						return 0;
					}
					keyLen = 32;
					if(tcWrapKey(TC_EFTYPE_SECRET+keyToExport,abComp1,(CK_ULONG_PTR)&keyLen))
					{
						multosBinToHex(abComp1,(char*)abComponentString,keyLen);
						printf("%s\n",abComponentString);
					}
					else
						printf("Key wrap failed.\n");
				}
			}
		}
		// ************** Import a key value wrapped by another **************************************
		else if (strcmp(argv[1],"-u") == 0)
		{
			keyLen = validateNumber(argv[2]);
			wFlags = parseFlags(argv[3]);
			parseLabel(argv[4],abLabel);
			i = validateNumber(argv[5]);
			parseHex(argv[6],abComp1,keyLen);
			parseHex(argv[7],abKcv,3);

			tcMseSetAlgo(TC_ALGO_AES_CBC,TC_TEMPLATE_CONFIDENTIALITY);
			tcMseSetKeyFile(TC_EFTYPE_SECRET+i,TC_TEMPLATE_CONFIDENTIALITY);

			if(!tcVerifyPIN2(TC_PINREF_K,abPIN))
			{
				printf("PIN invalid\n");
				multosReset();
				return 0;
			}

			if(tcUnwrapKey(wFlags,abLabel,abKcv,keyLen,abComp1,strlen(argv[6])/2,&handle))
				printf("Key unwrapped and imported OK\n");
			else
				printf("Operation failed\n");
		}
	}
	// Clear memory
	memset(abPIN,0,sizeof(abPIN));
	memset(abPINConf,0,sizeof(abPINConf));

	// Reset chip to force logouts
	multosReset();

	return 0;
}


