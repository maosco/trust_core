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
#include <unistd.h>
#include <sys/file.h>
#include <string.h>
#ifdef WIRINGPI
#include <wiringPi.h>		// GPIO
#include <wiringPiI2C.h>   // I2C
#else
#include <pigpiod_if2.h>
#endif
#include "platform.h"

// I2C bus address of MULTOS device
#define MULTOS_SLAVE_DEVICE 0x5F

// Constants for the transport protocol. Do not remove or change.
#define MULTOS_RESPONSE_TAG_REG 0x80
#define MULTOS_RESPONSE_TAG_LEN 0x81
#define MULTOS_MASTER_I2C_BUFSIZE_REG 0x83

#ifdef WIRINGPI

// Physical pin numbering scheme
#define MULTOS_RESET_PIN 11
#define SCL_MONITOR_PIN 13

// File Descriptor for I2C connection
int i2cFd = -1;

// This function is needed on the RPi because it doesn't support i2c clock stretching
// The idea is to start the first read of a response which causes the slave to stretch
// the clock until it has a reply ready. This function detects the clock going high again.
// Normal reading can then resume.
int waitI2C(unsigned long maxWait)
{
	unsigned long waitTimeLeft = maxWait * 1000;
	int waitNeeded;

	char c = MULTOS_RESPONSE_TAG_REG;
	write(i2cFd,&c,1);
	read(i2cFd,&c,1);
	usleep(5);

	waitNeeded = 1 - digitalRead(SCL_MONITOR_PIN);
    while(digitalRead(SCL_MONITOR_PIN) == 0 && waitTimeLeft > 0)
    {
	  usleep(100);
	  waitTimeLeft -= 100;
    }
    if(waitTimeLeft > 0)
    {
    	if(waitNeeded || c == MULTOS_RESPONSE_TAG_REG)
    		read(i2cFd,&c,1);
    	return (c);
    }
    fprintf(stderr,"Timeout\n");
    fflush(stderr);
    return(-1);
}

int readI2C(unsigned char *reply, int len)
{
  int i = 0;

  i = read(i2cFd,reply,len);

  return (i);
}

// Send one block of data over I2C interface
int writeToI2C(unsigned char *buff, int len)
{
	int n = write(i2cFd,buff,len);
	usleep(10);
	return n;
}

int multosInit(void)
{
	// Set up GPIO
	if(wiringPiSetupPhys() == -1)
	{
		fprintf(stderr,"Failed to initialise GPIO.\n");
		return(0);
	}

	// The RPi doesn't support i2c clock stretching. This is a workaround to use another
	// pin to monitor the clock in the function waitI2C()
	pinMode(SCL_MONITOR_PIN,INPUT);

	// Set up reset pin (falling edge triggers a reset on MULTOS)
	pinMode(MULTOS_RESET_PIN,OUTPUT);
	digitalWrite(MULTOS_RESET_PIN, 1);
	sleep(1);

	// Connect to I2C device
	i2cFd = wiringPiI2CSetup(MULTOS_SLAVE_DEVICE);

	if(i2cFd < 0)
		return (0);

	return(1);
}

int multosReset(void)
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

// Broadcom GPIO PIN numbers
// Use shell command "pinout" to get the numbers
#define MULTOS_RESET_PIN 17
#define SCL_MONITOR_PIN 27

// Daemon connection ID
int pi = 0;

// I2C device handle
int i2cFd = PI_NO_HANDLE;

// Raspbian version
int raspbian = 0;


// This function is needed on the RPi because it doesn't support i2c clock stretching
// The idea is to start the first read of a response which causes the slave to stretch
// the clock until it has a reply ready. This function detects the clock going high again.
// Normal reading can then resume.
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

int multosInit(void)
{
	FILE *fp;
	char line[128];

	// Get the Raspbian version
	fp = fopen("/etc/issue","r");
	if (fp)
	{
		fgets(line,sizeof(line),fp);
		fclose(fp);
		if (strncmp(line,"Raspbian GNU/Linux 11",21) == 0)
			raspbian = 11;
	}

	// Set up GPIO using local daemon
	pi = pigpio_start(NULL,NULL);
	if(pi < 0)
	{
		fprintf(stderr,"Failed to connect to pigpiod.\n");
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
		return (0);

	return(1);
}

int multosReset(void)
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
