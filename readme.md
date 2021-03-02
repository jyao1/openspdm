# This openspdm is a sample implementation for the DMTF [SPDM](https://www.dmtf.org/standards/pmci) specification

## NOTE
We are moving openspdm to a new location. We freeze the master at this moment.
Once the new location is finalized, we will move development activity there.

## Feature

1) Specification

   The SPDM and secured message follow :

   DSP0274  Security Protocol and Data Model (SPDM) Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.0.0.pdf) and version [1.1.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.0.pdf))

   DSP0277  Secured Messages using SPDM Specification (version [1.0.0b](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.0.0b.pdf))

   The MCTP and secured MCTP follow :

   DSP0275  Security Protocol and Data Model (SPDM) over MCTP Binding Specification (version [1.0.0](https://www.dmtf.org/sites/default/files/standards/documents/DSP0275_1.0.0.pdf))

   DSP0276  Secured MCTP Messages over MCTP Binding Specification (version [1.0.0a](https://www.dmtf.org/sites/default/files/standards/documents/DSP0276_1.0.0a.pdf))

   The PCI DOE / IDE follow :

   PCI  Data Object Exchange (DOE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14143)

   PCI  Component Measurement and Authentication (CMA) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/14236)

   PCI  Integrity and Data Encryption (IDE) [ECN](https://members.pcisig.com/wg/PCI-SIG/document/15149)

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

   Support to be included in UEFI host environment [EDKII](https://github.com/tianocore/edk2), such as [SpdmRequester](https://github.com/jyao1/edk2/tree/DeviceSecurity/DeviceSecurityPkg)

   Support to be included in [OpenBMC](https://github.com/openbmc). It is in planning, see [SPDM Integration](https://www.youtube.com/watch?v=PmgXkLJYI-E).

## Document

1) Presentation

   Open Source Firmware Conference 2020 - [openspdm](https://cfp.osfc.io/osfc2020/talk/ECQ88N/)

2) openspdm library design:

   The detailed design can be found at [Design](https://github.com/jyao1/openspdm/blob/master/Doc/Design.md)

3) openspdm user guide:

   The user guide can be found at [UserGuide](https://github.com/jyao1/openspdm/blob/master/Doc/UserGuide.md)


## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (VS2015 or VS2019)

2) [GCC](https://gcc.gnu.org/) (above GCC5)

3) [LLVM](https://llvm.org/) (LLVM9)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

4) [cmake](https://cmake.org/). It will be used to replace makefile.

### Crypto library

1) [MbedTls](https://tls.mbed.org) as Crypto library

   Please download [mbedtls-2.16.6](https://tls.mbed.org/download/start/mbedtls-2.16.6-apache.tgz) and unzip it.
   Rename mbedtls-2.16.6 to mbedtls and put mbedtls under [MbedTlsLib](https://github.com/jyao1/openspdm/tree/master/OsStub/MbedTlsLib)

2) [Openssl](https://www.openssl.org) as crypto library

   Please download [openssl-1.1.1g](https://www.openssl.org/source/openssl-1.1.1g.tar.gz) and unzip it.
   Rename openssl-1.1.1g to openssl and put openssl under [OpensslLib](https://github.com/jyao1/openspdm/tree/master/OsStub/OpensslLib)

### Unit Test framework

1) [cmocka](https://cmocka.org/)

   Please download [cmocka-1.1.5](https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz) and unzip it.
   Rename cmocka-1.1.5 to cmocka and put cmocka under [CmockaLib](https://github.com/jyao1/openspdm/tree/master/UnitTest/CmockaLib)

## Build

### Windows Build:

1) Use Visual Studio

   Tool : Visual Studio 2015 (TOOLCHAIN=VS2015)

   Open visual studio 2015 command prompt at openspdm dir and type `nmake ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

   Tool : Visual Studio 2019 (TOOLCHAIN=VS2019)

   Open visual studio 2019 command prompt at openspdm dir and type `nmake ARCH=<X64|Ia32> TOOLCHAIN=VS2019 TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

2) Use LLVM

   Tool : LLVM x86_64-pc-windows-msvc (TOOLCHAIN=CLANG)

   Open visual studio 2019 command prompt at openspdm dir and type `make ARCH=<X64|Ia32> TOOLCHAIN=CLANG TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

### Linux Build:

1) Use GCC

   Tool : GCC (TOOLCHAIN=GCC)

   Open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`.

2) Use LLVM

   Tool : LLVM (TOOLCHAIN=CLANG)

   Open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=<X64|Ia32> TOOLCHAIN=CLANG TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`.

### Build with CMake

   We will use CMake to replace makefile in the future, after all features are enabled.
   Currently, only SpdmEmu and UnitTest are enabled with VS2019 and GCC.

1) Use CMake in Linux (Toolchain=GCC|CLANG)

   ```
   cd openspdm
   mkdir build
   cd build
   cmake -DARCH=<X64|Ia32> -DTOOLCHAIN=<Toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<MbedTls|Openssl> -DTESTTYPE=<SpdmEmu|UnitTest> ..
   make CopyTestKey
   make
   ```

2) Use CMake in Windows (Toolchain=VS2019|VS2015|CLANG)

   Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64.
   ```
   cd openspdm
   mkdir build
   cd build
   cmake -G"NMake Makefiles" -DARCH=<X64|Ia32> -DTOOLCHAIN=<Toolchain> -DTARGET=<Debug|Release> -DCRYPTO=<MbedTls|Openssl> -DTESTTYPE=<SpdmEmu|UnitTest> ..
   nmake CopyTestKey
   nmake
   ```

## Run Test

### Run [SpdmEmu](https://github.com/jyao1/openspdm/tree/master/SpdmEmu)

   The SpdmEmu output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>.
   Open one command prompt at output dir to run `SpdmResponderEmu` and another command prompt to run `SpdmRequesterEmu`.

   Please refer to [SpdmEmu](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmEmu.md) for detail.

### Run [UnitTest](https://github.com/jyao1/openspdm/tree/master/UnitTest)

   The UnitTest output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>.
   Open one command prompt at output dir to run `TestSpdmRequester > NUL` and `TestSpdmResponder > NUL`.

   You may see something like:

   <pre>
      [==========] Running 2 test(s).
      [ RUN      ] TestSpdmResponderVersionCase1
      [       OK ] TestSpdmResponderVersionCase1
      [ RUN      ] TestSpdmResponderVersionCase2
      [       OK ] TestSpdmResponderVersionCase2
      [==========] 2 test(s) run.
      [  PASSED  ] 2 test(s).
   </pre>

### [SpdmDump](https://github.com/jyao1/openspdm/tree/master/SpdmDump) tool

   The tool output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. It can be used to parse the pcap file for offline analysis.

   Please refer to [SpdmDump](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmDump.md) for detail. 

### Other Test

  openspdm also supports other test such as code coverage, fuzzing, symbolic execution, model checker.

  Please refer to [Test](https://github.com/jyao1/openspdm/blob/master/Doc/Test.md) for detail. 

## Feature not implemented yet

1) Please refer to [issues](https://github.com/jyao1/openspdm/issues) for detail

## Contribution

1) Please refer to [contribution](https://github.com/jyao1/openspdm/blob/master/contribution.md) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

