# This openspdm is a sample implementation for the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## Feature

1) Specification

   DSP0274	Security Protocol and Data Model (SPDM) Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf) and version [1.1.0b](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0b.pdf))

   DSP0276	Secured MCTP Messages over MCTP Binding Specification (version [1.0.0a](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0a.pdf))

2) Both SPDM requester and SPDM responder.

3) Programming Context:

   No heap is required in the SPDM lib.
   No writable global variable is required in the SPDM lib. 

4) Implemented command and response: 

   SPDM 1.0: GET_VERSION, GET_CAPABILITY, NEGOTIATE_ALGORITHM, GET_DIGEST, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENT.

   SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION.

5) Cryptographic algorithm support:

   The SPDM lib requires [cryptolib API](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseCryptLib.h), including random number, symmetric crypto, asymmetric crypto, hash and message authentication code etc.

   An [openssl](https://www.openssl.org/) wrapper is included in [BaseCryptLib](https://github.com/jyao1/openspdm/tree/master/OsStub/BaseCryptLib).

   NOTE: To support other cryptographic library is TBD.

6) Execution context:

   Support to build an OS application for SpdmRequester and SpdmResponder to trace the communication.

   Support to be included in UEFI host environment, such as [SpdmRequester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

## Build

Crypto library :
  Please download [openssl-1.1.1b](https://www.openssl.org/source/openssl-1.1.1b.tar.gz) and unzip it.
  Rename openssl-1.1.1b to openssl and put openssl under [OpensslLib](https://github.com/jyao1/openspdm/tree/master/OsStub/OpensslLib)

Windows Build tool :
  Visual Studio 2015

Windows Build :
  Open command prompt at openspdm dir and type "nmake".
  The output is at openspdm\Build\DEBUG_VS2015\X64.

Linux Build tool :
  GCC

Linux Build:
  Open command prompt at openspdm dir and type "make -f GNUmakefile  -e WORKSPACE=~/openspdm".
  The output is at openspdm\Build\DEBUG_GCC\X64.

Run :
  Open one command prompt at output dir to run SpdmResponderTest and another command prompt to run SpdmRequesterTest.

NOTE:
  Current version only supports build with "Visual Studio 2015" and X64 version.
  Supporting for more compilers such as VS2019, GCC or LLVM, and architectures such as IA32 are in the progress.

## Feature not implemented yet

1) multiple algorithms (SHA3, RSASSA-PSS, ECDSA, AEAD-ChaCha20Poly1305, etc)

2) SPDM 1.0

   multiple cert chains

3) SPDM 1.1

   multiple sessions

   mutual authentication (ENCAPSULATED message)

   command and response: HEARTBEAT, KEY_UPDATE, GET_ENCAPSULATED

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

