# Test in openspdm

Besides OsTest and UnitTest introduced in readme, openspdm also supports some other tests.

## Prerequisit

### Code Coverage Tool

1) [DynamoRIO](https://dynamorio.org/) for Windows

   Download and install [DynamoRIO 8.0.0](https://github.com/DynamoRIO/dynamorio/wiki/Downloads).
   Then `set DRIO_PATH=<DynameRIO_PATH>`

   Install Perl [ActivePerl 5.26](https://www.activestate.com/products/perl/downloads/).

2) [lcov](http://ltp.sourceforge.net/coverage/lcov.php) for Linux

   Install lcov `sudo apt-get install lcov`.

### Fuzzing Tool

1) [AFL](https://lcamtuf.coredump.cx/afl/) for Linux

   Download and install [AFL](http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz). Unzip and build it with `make`. Ensure AFL binary is in PATH environment variable. Then:
   ```
   sudo bash -c 'echo core >/proc/sys/kernel/core_pattern'
   cd /sys/devices/system/cpu/
   sudo bash -c 'echo performance | tee cpu*/cpufreq/scaling_governor'
   ```

2) [winafl](https://github.com/googleprojectzero/winafl) for Windows

   Clone [winafl](https://github.com/googleprojectzero/winafl).
   Download [DynamoRIO](https://dynamorio.org/).

### Symbolic Execution Tool

1) [KLEE](https://klee.github.io/)

   Download and install [KLEE](https://klee.github.io/build-llvm9/) with LLVM9.

### Model Checker Tool

1) [CBMC](http://www.cprover.org/cbmc/)

   Install [CBMC tool](http://www.cprover.org/cprover-manual/). For Windows, unzip [cbmc-5-10-win](http://www.cprover.org/cbmc/download/cbmc-5-10-win.zip). For Linux, unzip [cbmc-5-11-linux-64](http://www.cprover.org/cbmc/download/cbmc-5-11-linux-64.tgz). Ensure CBMC executable directory is in PATH environment variable.

## Run Test

### Collect Code Coverage

1) Code Coverage in Windows with [DynamoRIO](https://dynamorio.org/)

   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests and generate log file :
   `%DRIO_PATH%\<bin64|bin32>\drrun.exe -c %DRIO_PATH%\tools\<lib64|lib32>\release\drcov.dll -- <test_app>`
   
   Generate coverage data with filter :
   `%DRIO_PATH%\tools\<bin64|bin32>\drcov2lcov.exe -dir . -src_filter openspdm`
   
   Generate coverage report :
   `perl %DRIO_PATH%\tools\<bin64|bin32>\genhtml coverage.info`

   The final report is index.html.

2) Code Coverage in Linux with GCC and [lcov](http://ltp.sourceforge.net/coverage/lcov.php).

   Goto openspdm/Build/\<TARGET>_\<TOOLCHAIN>/\<ARCH>. mkdir log and cd log.

   Run all tests.

   Collect coverage data :
   `lcov --capture --directory <openspdm_root_dir> --output-file coverage.info`

   Collect coverage report :
   `genhtml coverage.info --output-directory .`

   The final report is index.html.

### Run Fuzzing

1) Fuzzing in Linux with [AFL](https://lcamtuf.coredump.cx/afl/)
   
   ```
   mkdir testcase_dir
   mkdir /dev/shm/findings_dir
   cp <seed> testcase_dir
   afl-fuzz -i testcase_dir -o /dev/shm/findings_dir <test_app> @@
   ```
   Note: /dev/shm is tmpfs.

2) Fuzzing in Windows with [AFL](https://lcamtuf.coredump.cx/afl/)

   ```
   cp <test_app> winafl\<bin64|bin32>
   cp <test_app_pdb> winaft\<bin64|bin32>
   cd winaft\<bin64|bin32>
   afl-fuzz.exe -i in -o out -D %DRIO_PATH%\<bin64|bin32> -t 20000 -- -coverage_module <test_app> -fuzz_iterations 1000 -target_module <test_app> -target_method main -nargs 2 -- <test_app> @@
   ```

3) Fuzzing with LLVM [LibFuzzer](https://llvm.org/docs/LibFuzzer.html)  (TBD)

### Run Symbolic Execution

   Use KLEE to [generate ktest](https://klee.github.io/tutorials/testing-coreutils/):
   `klee --only-output-states-covering-new <test_app>`

   Transfer .ktest to seed file, which can be used for AFL-fuzzer. (TBD)

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
