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

## Prerequisit

### Build Tool

1) [Visual Studio](https://visualstudio.microsoft.com/) (2015 or 2019)

2) [GCC](https://gcc.gnu.org/)

3) [LLVM](https://llvm.org/)

   Download and install [LLVM9](http://releases.llvm.org/download.html#9.0.0). Ensure LLVM9 executable directory is in PATH environment variable.

### Crypto library

1) [MbedTls](https://tls.mbed.org) as Crypto library

   Please download [mbedtls-2.16.6](https://tls.mbed.org/download/start/mbedtls-2.16.6-apache.tgz) and unzip it.
   Rename mbedtls-2.16.6 to mbedtls and put mbedtls under [MbedTlsLib](https://github.com/jyao1/openspdm/tree/master/OsStub/MbedTlsLib)

2) [Openssl](https://www.openssl.org) as crypto library

   Please download [openssl-1.1.1b](https://www.openssl.org/source/openssl-1.1.1b.tar.gz) and unzip it.
   Rename openssl-1.1.1b to openssl and put openssl under [OpensslLib](https://github.com/jyao1/openspdm/tree/master/OsStub/OpensslLib)

### Unit Test framework

1) [cmocka](https://cmocka.org/)

   Please download [cmocka-1.1.5](https://cmocka.org/files/1.1/cmocka-1.1.5.tar.xz) and unzip it.
   Rename cmocka-1.1.5 to cmocka and put cmocka under [CmockaLib](https://github.com/jyao1/openspdm/tree/master/UnitTest/CmockaLib)

### Code Coverage Tool

1) [DynamoRIO](https://dynamorio.org/) for Windows

   Download and install [DynamoRIO 8.0.0](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).
   Then `set DRIO_PATH=<DynameRIO_PATH>`

   Install Perl [ActivePerl 5.26](https://www.activestate.com/products/perl/downloads/).

2) [lcov](http://ltp.sourceforge.net/coverage/lcov.php) for Linux

   Install lcov `sudo apt-get install lcov`.

### Model Checker Tool

1) [CBMC](http://www.cprover.org/cbmc/)

   Install [CBMC tool](http://www.cprover.org/cprover-manual/). For Windows, unzip [cbmc-5-10-win](http://www.cprover.org/cbmc/download/cbmc-5-10-win.zip). For Linux, unzip [cbmc-5-11-linux-64](http://www.cprover.org/cbmc/download/cbmc-5-11-linux-64.tgz). Ensure CBMC executable directory is in PATH environment variable.

## Build

### Windows Build:

1) Use Visual Studio

   Tool : Visual Studio 2015 (TOOLCHAIN=VS2015)

   Open visual studio 2015 command prompt at openspdm dir and type `nmake ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

   Tool : Visual Studio 2019 (TOOLCHAIN=VS2019)

   Open visual studio 2019 command prompt at openspdm dir and type `nmake ARCH=<X64|Ia32> TOOLCHAIN=VS2019 TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

2) Use LLVM

   Tool : LLVM9 x86_64-pc-windows-msvc (TOOLCHAIN=CLANG)

   Open visual studio 2019 command prompt at openspdm dir and type `make ARCH=<X64|Ia32> TOOLCHAIN=CLANG TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 and x64 command prompt for ARCH=X64)

### Linux Build:

1) Use GCC

   Tool : GCC (TOOLCHAIN=GCC)

   Open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`.

2) Use LLVM

   Tool : LLVM9 (TOOLCHAIN=CLANG)

   Open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=<X64|Ia32> TOOLCHAIN=CLANG TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>`.

## Run Test

### Run [OsTest](https://github.com/jyao1/openspdm/tree/master/OsTest)

   The OsTest output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>.
   Open one command prompt at output dir to run SpdmResponderTest and another command prompt to run SpdmRequesterTest.

### Run [UnitTest](https://github.com/jyao1/openspdm/tree/master/UnitTest)

   The UnitTest output is at openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>.
   Open one command prompt at output dir to run TestSpdmRequester and TestSpdmResponder.

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

### Collect Code Coverage

1) Code Coverage in Windows with [DynamoRIO](https://dynamorio.org/)

   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests and generate log file :
   `%DRIO_PATH%\bin64\drrun.exe -c %DRIO_PATH%\tools\lib64\release\drcov.dll -- XXX.exe` or 
   `%DRIO_PATH%\bin32\drrun.exe -c %DRIO_PATH%\tools\lib32\release\drcov.dll -- XXX.exe`
   
   Generate coverage data with filter :
   `%DRIO_PATH%\tools\bin64\drcov2lcov.exe -dir . -src_filter openspdm` or
   `%DRIO_PATH%\tools\bin32\drcov2lcov.exe -dir . -src_filter openspdm`
   
   Generate coverage report :
   `perl %DRIO_PATH%\tools\bin64\genhtml coverage.info` or
   `perl %DRIO_PATH%\tools\bin32\genhtml coverage.info`

   The final report is index.html.

2) Code Coverage in Linux with GCC and [lcov](http://ltp.sourceforge.net/coverage/lcov.php).

   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests.

   Collect coverage data :
   `lcov --capture --directory <openspdm_root_dir> --output-file coverage.info`

   Collect coverage report :
   `genhtml coverage.info --output-directory .`

   The final report is index.html.

### Run Model Checker

   Use [CBMC](http://www.cprover.org/cbmc/) as an example.

   For Windowns, open visual studio 2019 command prompt at openspdm dir and type `make ARCH=Ia32 TOOLCHAIN=CBMC TARGET=<DEBUG|RELEASE> CRYPTO=MbedTls -e WORKSPACE=<openspdm_root_dir>`. (Use x86 command prompt for ARCH=Ia32 only)

   For Linux, open command prompt at openspdm dir and type `make -f GNUmakefile ARCH=X64 TOOLCHAIN=CBMC TARGET=<DEBUG|RELEASE> CRYPTO=MbedTls -e WORKSPACE=<openspdm_root_dir>`.

   The output binary is created by the [goto-cc](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-cc.md).

   For more infomration on how to use [CBMC](https://github.com/diffblue/cbmc/), please refer to [CBMC Manual](https://github.com/diffblue/cbmc/tree/develop/doc/cprover-manual), such as [properties](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/properties.md), [modeling-nondeterminism](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/modeling-nondeterminism.md), [api](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/api.md). Example below:

   Using [goto-instrument](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/goto-instrument.md) static analyzer operates on goto-binaries and generate a modified binary:
   `goto-instrument SpdmRequester.exe SpdmRequester.gb <instrumentation-options>`

   Using [CBMC](https://github.com/diffblue/cbmc/blob/develop/doc/cprover-manual/cbmc-tutorial.md) on the modified binary:
   `cbmc SpdmRequester.gb --show-properties`

### Run Static Analysis

   Use [Klocwork](https://www.perforce.com/products/klocwork) as an example in windows.

   Install Klocwork and set environment.
   ```
   set KW_HOME=C:\Klocwork
   set KW_ROOT=%KW_HOME%\<version>\projects_root
   set KW_TABLE_ROOT=%KW_HOME%\Tables
   set KW_CONFIG=%KW_ROOT%\projects\workspace\rules\analysis_profile.pconf
   set KW_PROJECT_NAME=openspdm
   ```

   Build openspdm with Klocwork :
   ```
   kwinject --output %KW_ROOT%\%KW_PROJECT_NAME%.out nmake ARCH=<X64|Ia32> TARGET=<DEBUG|RELEASE> CRYPTO=<MbedTls|Openssl> -e WORKSPACE=<openspdm_root_dir>
   ```

   Collect analysis data :
   ```
   kwservice start
   kwadmin create-project %KW_PROJECT_NAME%
   kwadmin import-config %KW_PROJECT_NAME% %KW_CONFIG%
   kwbuildproject --project %KW_PROJECT_NAME% --tables-directory %KW_TABLE_ROOT%\%KW_PROJECT_NAME% %KW_ROOT%\%KW_PROJECT_NAME%.out --force
   kwadmin load %KW_PROJECT_NAME% %KW_TABLE_ROOT%\%KW_PROJECT_NAME%`
   ```

   View report at http://localhost:8080/.

## Feature not implemented yet

1) Other architectures such as Arm, AArch64, RiscV64, or Arc.

2) Please refer to [issues](https://github.com/jyao1/openspdm/issues) for detail

## Known limitation
This package is only the sample code to show the concept.
It does not have a full validation such as robustness functional test and fuzzing test. It does not meet the production quality yet.
Any codes including the API definition, the libary and the drivers are subject to change.

