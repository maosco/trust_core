/*
 * Copyright (c) 2020-2022, MULTOS Ltd
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

#include <Python.h>
#include <mtls.h>	// MULTOS TLS Shared Library header file
#include <string.h>


static PyObject* init(PyObject* self, PyObject *args)
{
	unsigned short wCipherSuite;
	int status = 1; // Returns 1 for OK. 0 for fail

	if(!PyArg_ParseTuple(args,"H",&wCipherSuite))
	{
		fprintf(stderr,"Invalid argument\n");
		status = 0;
	}
	else
		status = mtlsInit(wCipherSuite);
	return Py_BuildValue("i",status);
}

static PyObject* finish(PyObject* self, PyObject *args)
{
	int status = 1; // Returns 1 for OK. 0 for fail

	status = mtlsFinish();
	return Py_BuildValue("i",status);
}

static PyObject* version(PyObject* self, PyObject *args)
{
	unsigned char major,minor;
	PyObject *tuple;

	mtlsVersion(&major,&minor);

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",major));
	PyTuple_SetItem(tuple,1,Py_BuildValue("i",minor));
	return tuple;
}

static PyObject* generateRsaKeyPair(PyObject* self, PyObject *args)
{
	int status = 1; // Returns 1 for OK. 0 for fail
	char *sFileName;
	char *sCountryName;
	char *sStateOrProvinceName;
	char *sLocalityName;
	char *sOrgName;
	char *sOrgUnit;
	char *sCommonName;
	char *sEmailAddress;

	if(!PyArg_ParseTuple(args,"ssssssss",&sFileName,&sCountryName,&sStateOrProvinceName,&sLocalityName,&sOrgName,&sOrgUnit,&sCommonName,&sEmailAddress))
	{
		fprintf(stderr,"Invalid argument(s)\n");
		status = 0;
	}
	else
		status = mtlsGenerateRsaKeyPair(sFileName,sCountryName,sStateOrProvinceName,sLocalityName,sOrgName,sOrgUnit,sCommonName,sEmailAddress);

	return Py_BuildValue("i",status);
}

static PyObject* verifySignature(PyObject* self, PyObject *args)
{
	int status = 0; // Returns 1 for OK. 0 for fail
	Py_buffer modulus;
	Py_buffer exponent;
	Py_buffer data;
	Py_buffer signature;

	if(!PyArg_ParseTuple(args,"y*y*y*y*",&modulus, &exponent, &data,&signature))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsRsaVerifySignature(modulus.buf, modulus.len, exponent.buf, exponent.len, data.buf, data.len, signature.buf);

	return Py_BuildValue("i",status);
}

static PyObject* rsaSignPKCS1_type1(PyObject* self, PyObject *args)
{
	int sigLen = 0;
	Py_buffer data;
	PyObject *tuple;
	unsigned char doHash;
	unsigned char *pSig = NULL;

	if(!PyArg_ParseTuple(args,"y*b",&data,&doHash))
	{
		fprintf(stderr,"Invalid argument(s)\n");
		sigLen = 0;
	}
	else
		sigLen = mtlsRsaSignPKCS1_type1(data.buf,data.len,doHash,&pSig);

	// Construct return tuple
	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",sigLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)pSig,sigLen));
	if(pSig)
		free(pSig);
	return tuple;
}

static PyObject* rsaSignPKCS1_PSS(PyObject* self, PyObject *args)
{
	int sigLen = 0;
	Py_buffer data;
	PyObject *tuple;
	unsigned char doHash;
	unsigned char *pSig = NULL;

	if(!PyArg_ParseTuple(args,"y*b",&data,&doHash))
	{
		fprintf(stderr,"Invalid argument(s)\n");
		sigLen = 0;
	}
	else
		sigLen = mtlsRsaSignPKCS1_PSS(data.buf,data.len,doHash,&pSig);

	// Construct return tuple
	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",sigLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)pSig,sigLen));
	if(pSig)
		free(pSig);
	return tuple;
}

static PyObject* generateClientRandom(PyObject* self, PyObject *args)
{
	int outLen = 0;
	unsigned long dwServerTime;
	PyObject *tuple;
	unsigned char output[64];

	if(!PyArg_ParseTuple(args,"k",&dwServerTime))
	{
		fprintf(stderr,"Invalid argument(s)\n");
		outLen = 0;
	}
	else
		outLen = mtlsGenerateClientRandom(dwServerTime,dwServerTime == 0 ? 0 : 1, output, sizeof(output));

	// Construct return tuple
	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",outLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)output,outLen));
	return tuple;
}

static PyObject* generatePreMasterSecret(PyObject* self, PyObject *args)
{
	int outLen = 0;
	Py_buffer modulus;
	Py_buffer exponent;
	PyObject *tuple;
	unsigned char output[512];
	unsigned char major,minor;

	if(!PyArg_ParseTuple(args,"y*y*bb",&modulus, &exponent,&major,&minor))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		outLen = mtlsGeneratePreMasterSecret(major, minor, modulus.buf, modulus.len, exponent.buf, exponent.len, output, sizeof(output));

	// Construct return tuple
	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",outLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)output,outLen));
	return tuple;
}

static PyObject* generateMasterSecret(PyObject* self, PyObject *args)
{
	int status = 0; // Returns 1 for OK. 0 for fail
	Py_buffer server_random;

	if(!PyArg_ParseTuple(args,"y*",&server_random))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsGenerateMasterSecret(server_random.buf);

	return Py_BuildValue("i",status);
}

static PyObject* generateKeys(PyObject* self, PyObject *args)
{
	unsigned char *pClientIv;
	unsigned char *pServerIv;
	PyObject *tuple;
	int status = 0;
	
	status = mtlsGenerateKeys(&pClientIv,&pServerIv);
	
	tuple = PyTuple_New(3);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",status));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)pClientIv,16));
	PyTuple_SetItem(tuple,2,Py_BuildValue("y#",(char*)pServerIv,16));
	return tuple;
}

static PyObject* generateFinalFinishMAC(PyObject* self, PyObject *args)
{
	int outLen = 0;
	char *label;
	Py_buffer handshakeHash;
	PyObject *tuple;
	unsigned char output[64];

	if(!PyArg_ParseTuple(args,"sy*",&label,&handshakeHash))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		outLen = mtlsGenerateFinalFinishMAC(label,handshakeHash.buf, handshakeHash.len, output, sizeof(output));

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",outLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)output,outLen));

	return tuple;
}

static PyObject* handshakeHashInit(PyObject* self, PyObject *args)
{
	int status = mtlsHandshakeHashInit();

	return Py_BuildValue("i",status);
}

static PyObject* handshakeHashUpdate(PyObject* self, PyObject *args)
{
	int status = 0; // Returns 1 for OK. 0 for fail
	Py_buffer data;

	if(!PyArg_ParseTuple(args,"y*",&data))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsHandshakeHashUpdate(data.buf, data.len);

	return Py_BuildValue("i",status);
}

static PyObject* handshakeHashCurrent(PyObject* self, PyObject *args)
{
	int outLen = 0;
	PyObject *tuple;
	unsigned char output[64];

	outLen = mtlsHandshakeHashCurrent(output);

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",outLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)output,outLen));

	return tuple;
}

static PyObject* encryptDecrypt(PyObject* self, PyObject *args)
{
	unsigned short out_len = 0;
	Py_buffer seq_num;
	unsigned char content_type;
	unsigned short protocol_version;
	Py_buffer data;
	int sending;
	unsigned char *p = NULL;
	unsigned char ivOut[64];
	Py_buffer ivIn;
	PyObject *tuple;

	if(!PyArg_ParseTuple(args,"y*bHy*iy*",&seq_num, &content_type, &protocol_version, &data, &sending,&ivIn))
		fprintf(stderr,"Invalid argument(s)\n");
	else
	{
		// Copy the input data to a working buffer
		p = (unsigned char *)malloc(data.len * 2 + ivIn.len);
		if(p == NULL)
			fprintf(stderr,"malloc failed\n");
		else
		{
			// Copy input IV if decrypting
			if(!sending)
				memcpy(ivOut,ivIn.buf,(size_t)ivIn.len <= sizeof(ivOut) ? (size_t)ivIn.len : sizeof (ivOut));

			memcpy(p,data.buf,data.len);
			out_len = mtlsEncryptDecrypt(seq_num.buf,content_type,protocol_version,data.len,p,sending,ivOut);
		}
	}

	tuple = PyTuple_New(3);
	PyTuple_SetItem(tuple,0,Py_BuildValue("H",out_len));
	if(p)
	{
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,out_len));
		free(p);
	}
	else
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,0));
	if(sending && out_len > 0)
		PyTuple_SetItem(tuple,2,Py_BuildValue("y#",(char*)ivOut,16));
	else
		PyTuple_SetItem(tuple,2,Py_BuildValue("y#",(char*)ivOut,0));

	return tuple;
}

static PyObject* encryptDecryptOnly(PyObject* self, PyObject *args)
{
	int out_len = 0;
	Py_buffer data;
	int sending;
	unsigned char *p = NULL;
	unsigned char *iv = NULL;
	Py_buffer ivBuf;
	PyObject *tuple;

	if(!PyArg_ParseTuple(args,"y*iy*",&data, &sending,&ivBuf))
		fprintf(stderr,"Invalid argument(s)\n");
	else
	{
		// Copy the input data to a working buffer (needs to include space for the GCM mode Tag
		p = (unsigned char *)malloc(data.len + 16);
		if(p == NULL)
			fprintf(stderr,"malloc failed\n");
		else
		{
			memcpy(p,data.buf,data.len);

			// Set the required IV (if any)
			if(ivBuf.len > 0)
				iv = ivBuf.buf;
			out_len = mtlsEncryptDecryptOnly(p,data.len,sending,iv);
		}
	}

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",out_len));
	if(p && out_len > 0 )
	{
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,out_len));
	}
	else
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,0));
	if(p)
		free(p);
	return tuple;
}

static PyObject* hmac(PyObject* self, PyObject *args)
{
	int outLen = 0;
	Py_buffer data;
	unsigned char client;
	PyObject *tuple;
	unsigned char output[64];

	if(!PyArg_ParseTuple(args,"y*b",&data,&client))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		outLen = mtlsHMAC(data.buf,data.len,client,output,sizeof(output));

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",outLen));
	PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)output,outLen));

	return tuple;
}

static PyObject* generateRandom(PyObject* self, PyObject *args)
{
	unsigned short len;
	int status = 0; // Returns 1 for OK. 0 for fail
	unsigned char *p = NULL;
	PyObject *tuple;

	if(!PyArg_ParseTuple(args,"H",&len))
		fprintf(stderr,"Invalid argument(s)\n");
	else
	{
		// Copy the input data to a working buffer
		p = (unsigned char *)malloc(len);
		if(p == NULL)
			fprintf(stderr,"malloc failed\n");
		else
		{
			status = mtlsGenerateRandom(len,p);
		}
	}

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",status));
	if(p && status == 1)
	{
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,len));
	}
	else
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",(char*)p,0));
	if(p)
		free(p);
	return tuple;
}

static PyObject* ecdsaSign(PyObject* self, PyObject *args)
{
	Py_buffer hash;
	unsigned char sig[132]; // Biggest size for P-521 signature
	int sigLen = 0;
	PyObject *tuple;

	if(!PyArg_ParseTuple(args,"y*",&hash))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		sigLen = mtlsECDSASign(hash.buf,hash.len,sig);

	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("H",sigLen));
	if(sigLen > 0)
	{
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",sig,sigLen));
	}
	else
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",sig,0));

	return tuple;
}

static PyObject* ecdsaVerify(PyObject* self, PyObject *args)
{
	Py_buffer pubKey,data,signature;
	unsigned char namedCurve;
	int status = 0;

	if(!PyArg_ParseTuple(args,"y*by*y*",&pubKey,&namedCurve,&data,&signature))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsECDSAVerify(pubKey.buf,pubKey.len,namedCurve,data.buf,data.len,signature.buf);

	return Py_BuildValue("i",status);
}

static PyObject* setAdditionalData(PyObject* self, PyObject *args)
{
	Py_buffer data;
	int status = 0;

	if(!PyArg_ParseTuple(args,"y*",&data))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsSetAdditionalData(data.buf,data.len);

	return Py_BuildValue("i",status);
}
static PyObject* generateEphemeralECKey(PyObject* self, PyObject *args)
{
	unsigned char keyValue[132];
	int status = 0;
	unsigned char namedCurve;
	PyObject *tuple;
	int len = 64; // Assume P-256 public key length
	
	if(!PyArg_ParseTuple(args,"b",&namedCurve))
		fprintf(stderr,"Invalid argument(s)\n");
	else
		status = mtlsGenerateEphemeralECKey(namedCurve,keyValue);
	
	tuple = PyTuple_New(2);
	PyTuple_SetItem(tuple,0,Py_BuildValue("i",status));
	if(status == 1)
	{
		// Set public key length according to named curve value
		if(namedCurve == 24) //P-384
			len = 96;
		else if (namedCurve == 25) //P-521
			len = 132;
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",keyValue,len));
	}
	else
		PyTuple_SetItem(tuple,1,Py_BuildValue("y#",keyValue,0));

	return tuple;	
}
// ------------------------------------- PYTHON MODULE HOOKS ----------------------------------------------------------

static PyMethodDef Methods[] = {
		{"init", init, METH_VARARGS, "Initialise HAL, select MULTOS app and intialise ciphersuite (if supplied)"},
		{"finish", finish, METH_VARARGS, "Erase key data and terminate current session"},
		{"version", version, METH_VARARGS, "Returns the version of the underlying TLS library"},
		{"generateRsaKeyPair", generateRsaKeyPair, METH_VARARGS, "Generate RSA key pair and self-signed PEM formatted certificate request"},
		{"verifySignature", verifySignature, METH_VARARGS, "Verify signature for given data"},
		{"rsaSignPKCS1_type1",rsaSignPKCS1_type1,METH_VARARGS, "PKCS#1 v1.15 signature with type 1 padding"},
		{"rsaSignPKCS1_PSS",rsaSignPKCS1_PSS,METH_VARARGS,"PKCS#1 signature with PSS padding"},
		{"generateClientRandom",generateClientRandom,METH_VARARGS,"Generate client random optionally including server time"},
		{"generatePreMasterSecret",generatePreMasterSecret,METH_VARARGS,"Generate Pre Master Secret and encrypt to the RSA public key provided"},
		{"generateMasterSecret",generateMasterSecret,METH_VARARGS,"Generate Master Secret using the server random and previously generated client random"},
		{"generateKeys",generateKeys,METH_VARARGS,"Generate and securely store the session keys"},
		{"generateFinalFinishMAC",generateFinalFinishMAC,METH_VARARGS,"Compute MAC for Client Finished and Server Finished messages"},
		{"handshakeHashInit",handshakeHashInit,METH_VARARGS,"Initialise the handshake hash"},
		{"handshakeHashUpdate",handshakeHashUpdate,METH_VARARGS,"Update the handshake hash with new data"},
		{"handshakeHashCurrent",handshakeHashCurrent,METH_VARARGS,"Get the current value of the handshake hash"},
		{"encryptDecrypt",encryptDecrypt,METH_VARARGS,"Encrypt or Decrypt a message with HASH-MAC"},
		{"encryptDecryptOnly",encryptDecryptOnly,METH_VARARGS,"Encrypt or Decrypt a message without HASH-MAC"},
		{"hmac",hmac,METH_VARARGS,"Compute HASH-MAC using computed session key over given data"},
		{"generateRandom",generateRandom,METH_VARARGS,"Generate a random block of bytes of given length"},
		{"ecdsaSign",ecdsaSign,METH_VARARGS,"Sign the provided hash using ECDSA"},
		{"ecdsaVerify",ecdsaVerify,METH_VARARGS,"Verify the provided signature using ECDSA"},
		{"setAdditionalData",setAdditionalData,METH_VARARGS,"Set the additional data for AES-GCM encryption/decryption"},
		{"generateEphemeralECKey",generateEphemeralECKey,METH_VARARGS,"Create the Ephemeral Key for ECDHE"},
		{NULL, NULL, 0, NULL}
};


static struct PyModuleDef pymultosTLS_definition = {
		PyModuleDef_HEAD_INIT, "pymultosTLS", "MULTOS TLS 1.2 Cryptographic Functions", -1, Methods};

PyMODINIT_FUNC PyInit_pymultosTLS(void) {
	Py_Initialize();
	return PyModule_Create(&pymultosTLS_definition);
}
