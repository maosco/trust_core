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

#ifndef MULTOSSERIALINTERFACE_MULTOSSHARED_H_
#define MULTOSSERIALINTERFACE_MULTOSSHARED_H_


#define MULTOS_SHARED_MEM_LOC "/tmp/multosShared"
#define BYTE unsigned char
#define WORD unsigned short
#define DWORD unsigned long
#define MULTOS_SHARED_MAX_DATA 3000

// Status values below with (d) mean daemon sets and (c) means clients set.
// OFFLINE(d) - Daemon not running or not connected
// AVAILABLE(d) - Daemon is available for client connections - 100ms poling
// ERROR(d) - An error occurred in the Daemon comms with the device. Daemon should attempt to restart itself.
// REQUESTED(c) - Client has requested connection
// CONNECTED(d) - Client has locked Daemon pending message exchange(s) - 10ms poling
// CMD_READY(c) - Client has placed a command to be processed
// CMD_PROCESSING(d) - Command in process
// RESULT_AVAILABLE(d) - Command was processed OK and awaits collection. Back to 100ms polling.
// DISCONNECT(c) - Client requesting disconnection
enum eMultosSharedStatus { OFFLINE, AVAILABLE, REQUESTED, CONNECTED, CMD_READY, CMD_PROCESSING, RESULT_AVAILABLE, DISCONNECT, EMBEDDED_MODE, ERROR };

typedef struct {
	BYTE status;
	DWORD requestingPid; // Set by the client
	DWORD connectedPid;  // Set by the server
	BYTE CLA, INS, P1, P2;
	WORD Lc, Le, La;
	BYTE case4;
	WORD SW12;
	BYTE data[MULTOS_SHARED_MAX_DATA];
	DWORD timeout;
} multosShared_t;

#endif /* MULTOSSERIALINTERFACE_MULTOSSHARED_H_ */
