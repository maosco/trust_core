The projects in this workspace are ready to build on a Raspberry Pi 3B or 3B+.

The workspace folder must be copied to /home/pi

Obtaining PKCS#11 Header Files
==============================
To obtain the header files for PKCS#11 2.40 (pkcs11.h, pkcs11f.h and pkcs11t.h) please follow these instructions

$ cd workspace/cryptoki.so
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h

These platform specific macros must be included in pkcs11.h at line 184

// Platform specific macros - for Raspberry Pi
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

Building Projects
=================
The workspace/build script builds the projects in the required order and copies files to where they are to be used.

Setting up Trust Core driver to start at boot
=============================================
The following commands should be executed with sudo
$ cp multos.sh /etc/init.d
$ cd /etc/init.d
$ chmod +x multos.sh
$ update-rc.d multos.sh defaults

A reboot is required for this to take effect.
