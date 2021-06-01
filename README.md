The projects in "workspace" are ready to build on a Raspberry Pi 3B or 3B+.

The workspace folder must be copied to /home/pi

Obtaining PKCS#11 Header Files
==============================
To obtain the header files for PKCS#11 2.40 (pkcs11.h, pkcs11f.h and pkcs11t.h) please follow these instructions

```
$ cd workspace/cryptoki.so
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h
$ wget http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h
```

These platform specific macros must be included in pkcs11.h at line 184

```
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
```

Building Projects
=================
The workspace/build script builds the projects in the required order and copies files to where they are to be used.

Setting up Trust Core driver to start at boot
=============================================
The following commands should be executed with sudo

```
$ cp multos.sh /etc/init.d
$ cd /etc/init.d
$ chmod +x multos.sh
$ update-rc.d multos.sh defaults
```

A reboot is required for this to take effect.

Building for Windows
====================
The basic tools (lsm, loadm and deletem) plus the PKCS#11 DLL (cryptoki) and management tools (p11keygen, p11keyman and p11pinman) can be built for WIN32.

The PKCS#11 platform specific macros for Windows are:

```
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType name
#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
```

The Windows directory contains the hardware abstraction layer required for WIN32. It makes use of this device http://www.robot-electronics.co.uk/htm/usb_iss_tech.htm. This is also the same interface used by the Digiseq P5 MULTOS dongle.

Notes:

- In platform.c there is a #define for utilising the hard reset of the MULTOS chip via the USB-ISS device's I/O1 pin. By default this is off.
- The environment variable MULTOS_I2C_COMPORT is used to specify the COM port (e.g. COM3) used by the USB-ISS device.
- The basic tools (lsm, loadm and deletem) all depend on the HAL (multosio_i2c) for compilation and linking.
- The PKCS#11 dll depends on the HAL for compilation and linking
- p11keygen depends upon PKCS#11 for compilation; for linking it depends upon PKCS#11 and the HAL.
- p11keyman and p11pinman also depend upon the HAL, but instead of the whole PKCS#11 environment they depend just on cryptoki/tc_api.h (for compilation) and cyptoki/tc_api.obj (for linking).



