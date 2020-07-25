# This openspdm is a sample implementation for the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## Feature

1) Specification

   DSP0274	Security Protocol and Data Model (SPDM) Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf) and version [1.1.0c](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0c.pdf))

   DSP0276	Secured MCTP Messages over MCTP Binding Specification (version [1.0.0a](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0a.pdf))

2) Both SPDM requester and SPDM responder.

3) Programming Context:

   No heap is required in the SPDM lib.
   No writable global variable is required in the SPDM lib. 

4) Implemented command and response: 

   SPDM 1.0: GET_VERSION, GET_CAPABILITY, NEGOTIATE_ALGORITHM, GET_DIGEST, GET_CERTIFICATE, CHALLENGE, GET_MEASUREMENT.

   SPDM 1.1: KEY_EXCHANGE, FINISH, PSK_EXCHANGE, PSK_FINISH, END_SESSION, HEARTBEAT, KEY_UPDATE, ENCAPSULATED message

5) Cryptographic algorithm support:

   The SPDM lib requires [cryptolib API](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseCryptLib.h), including random number, symmetric crypto, asymmetric crypto, hash and message authentication code etc.

   Current support algorithm: SHA-2, RSA-SSA/ECDSA, FFDHE/ECDHE, AES_GCM/ChaCha20Poly1305, HMAC.

   An [MbedTls](https://tls.mbed.org/) wrapper is included in [BaseCryptLibMbedTls](https://github.com/jyao1/openspdm/tree/master/OsStub/BaseCryptLibMbedTls).

   An [Openssl](https://www.openssl.org/) wrapper is included in [BaseCryptLibOpenssl](https://github.com/jyao1/openspdm/tree/master/OsStub/BaseCryptLibOpenssl).

6) Execution context:

   Support to build an OS application for SpdmRequester and SpdmResponder to trace the communication.

   Support to be included in UEFI host environment, such as [SpdmRequester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

## Build

1) Download Crypto library :

   To use MbedTls as Crypto librarym, Please download [mbedtls-2.16.6](https://tls.mbed.org/download/start/mbedtls-2.16.6-apache.tgz) and unzip it.
   Rename mbedtls-2.16.6 to mbedtls and put mbedtls under [MbedTlsLib](https://github.com/jyao1/openspdm/tree/master/OsStub/MbedTlsLib)

   To use Openssl as crypto library, please download [openssl-1.1.1b](https://www.openssl.org/source/openssl-1.1.1b.tar.gz) and unzip it.
   Rename openssl-1.1.1b to openssl and put openssl under [OpensslLib](https://github.com/jyao1/openspdm/tree/master/OsStub/OpensslLib)

2) Windows Build:

   Tool : Visual Studio 2015 (TOOLCHAIN=VS2015)

   Open command prompt at openspdm dir and type "nmake ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>".

3) Linux Build:

   Tool : GCC (TOOLCHAIN=GCC)

   Open command prompt at openspdm dir and type "make -f GNUmakefile ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>".

   Tool : CLANG (TOOLCHAIN=CLANG)

   Open command prompt at openspdm dir and type "make -f GNUmakefile ARCH=<X64|Ia32> TOOLCHAIN=CLANG TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>".

4) Run :
   The output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>.
   Open one command prompt at output dir to run SpdmResponderTest and another command prompt to run SpdmRequesterTest.

## Feature not implemented yet

1) Other architectures such as Arm, AArch64, RiscV64, or Arc.

2) Please refer to [issues](https://github.com/jyao1/openspdm/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

