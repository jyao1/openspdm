cmake_minimum_required(VERSION 2.6)

project("openspdm" C)

#
# Build Configuration Macro Definition
#
MESSAGE("#########################")
MESSAGE("## Build Configuration ##")
MESSAGE("#########################")

SET(ARCH ${ARCH} CACHE STRING "Choose the arch of build: Ia32 X64" FORCE)
SET(TOOLCHAIN ${TOOLCHAIN} CACHE STRING "Choose the toolchain of build: GCC CLANG CBMC AFL KLEE LIBFUZZER" FORCE)
SET(CMAKE_BUILD_TYPE ${TARGET} CACHE STRING "Choose the target of build: Debug Release" FORCE)
SET(CRYPTO ${CRYPTO} CACHE STRING "Choose the crypto of build: MbedTls Openssl" FORCE)
SET(TESTTYPE ${TESTTYPE} CACHE STRING "Choose the test type for openspdm: OsTest UnitTest UnitFuzzing" FORCE)

if(ARCH STREQUAL "X64")
    MESSAGE("ARCH = X64")
elseif(ARCH STREQUAL "Ia32")
    MESSAGE("ARCH = Ia32")
else()
    MESSAGE(FATAL_ERROR "Unkown ARCH")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "GCC")
        MESSAGE("TOOLCHAIN = GCC")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        MESSAGE("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "CBMC")
        MESSAGE("TOOLCHAIN = CBMC")
    elseif(TOOLCHAIN STREQUAL "AFL")
        MESSAGE("TOOLCHAIN = AFL")
    elseif(TOOLCHAIN STREQUAL "KLEE")
        MESSAGE("TOOLCHAIN = KLEE")
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        MESSAGE("TOOLCHAIN = LIBFUZZER")
    else()
        MESSAGE(FATAL_ERROR "Unkown TOOLCHAIN")
    endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "VS2015")
        MESSAGE("TOOLCHAIN = VS2015")
    elseif(TOOLCHAIN STREQUAL "VS2019")
        MESSAGE("TOOLCHAIN = VS2019")
    elseif(TOOLCHAIN STREQUAL "CLANG")
        MESSAGE("TOOLCHAIN = CLANG")
    elseif(TOOLCHAIN STREQUAL "CBMC")
        MESSAGE("TOOLCHAIN = CBMC")
    else()
        MESSAGE(FATAL_ERROR "Unkown TOOLCHAIN")
    endif()
else()
    MESSAGE(FATAL_ERROR "${CMAKE_SYSTEM_NAME} is not supportted")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    MESSAGE("TARGET = Debug")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    MESSAGE("TARGET = Release")
else()
    MESSAGE(FATAL_ERROR "Unkown build type")
endif()

if(CRYPTO STREQUAL "MbedTls")
    MESSAGE("CRYPTO = MbedTls")
elseif(CRYPTO STREQUAL "Openssl")
    MESSAGE("CRYPTO = Openssl")
else()
    MESSAGE(FATAL_ERROR "Unkown CRYPTO")
endif()

if(TESTTYPE STREQUAL "OsTest")
    MESSAGE("TESTTYPE = OsTest")
elseif(TESTTYPE STREQUAL "UnitTest")
    MESSAGE("TESTTYPE = UnitTest")
elseif(TESTTYPE STREQUAL "UnitFuzzing")
    MESSAGE("TESTTYPE = UnitFuzzing")
else()
    MESSAGE(FATAL_ERROR "Unkown TESTTYPE")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    if(TOOLCHAIN STREQUAL "GCC")
        SET(CMAKE_C_COMPILER gcc) 
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall -Werror -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -fno-stack-protector -maccumulate-outgoing-args -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO -Wno-switch -Wno-maybe-uninitialized -Wno-uninitialized  -Wno-builtin-declaration-mismatch -Wno-nonnull-compare --coverage -fprofile-arcs -ftest-coverage")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include Base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")
        
        SET(CMAKE_AR gcc-ar)
        
        SET(CMAKE_EXE_LINKER_FLAGS "-Wno-error -no-pie" )

    elseif(TOOLCHAIN STREQUAL "CLANG")
        SET(CMAKE_C_COMPILER clang) 
        SET(CMAKE_C_FLAGS "-g -fshort-wchar -fno-strict-aliasing -Wall  -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -fno-stack-protector  -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO -Wno-switch")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include Base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")
        
        SET(CMAKE_AR llvm-ar)
        
        SET(CMAKE_EXE_LINKER_FLAGS "-Wno-error -no-pie" )
    elseif(TOOLCHAIN STREQUAL "CBMC")
        MESSAGE("TOOLCHAIN=CBMC")
    elseif(TOOLCHAIN STREQUAL "AFL")
        MESSAGE("TOOLCHAIN=AFL")
    elseif(TOOLCHAIN STREQUAL "KLEE")
        SET(CMAKE_C_COMPILER clang) 
        SET(CMAKE_C_FLAGS "-g -fno-strict-aliasing -Wall  -Wno-array-bounds -ffunction-sections -fdata-sections -fno-common -fno-stack-protector  -mno-red-zone -Wno-address -fpie -fno-asynchronous-unwind-tables -flto -DUSING_LTO -Wno-switch -emit-llvm -DTEST_WITH_KLEE=TRUE -DDEBUG_ASSERT_CHOICE=0")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "-include Base.h -Wno-error=maybe-uninitialized -Wno-error=format -Wno-format -Wno-error=unused-but-set-variable")
        SET(CMOCKA_FLAGS "-std=gnu99 -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -fno-common -Wformat -fno-common -fstack-protector-strong")
        
        SET(CMAKE_AR llvm-ar)
        
        SET(CMAKE_LINKER llvm-link)
    elseif(TOOLCHAIN STREQUAL "LIBFUZZER")
        MESSAGE("TOOLCHAIN=LIBFUZZER")
    endif()

    SET(CMAKE_C_FLAGS_RELEASE     "-Os")
    SET(CMAKE_C_FLAGS_DEBUG       "-O0")

    if(ARCH STREQUAL "X64")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -DNO_MSABI_VA_FUNCS -mcmodel=small")
    elseif(ARCH STREQUAL "Ia32")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    endif()

elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHAIN STREQUAL "CLANG")
        SET(CMAKE_C_COMPILER clang-cl.exe)
        SET(CMAKE_C_FLAGS "-fno-strict-aliasing -Wall  -Wno-array-bounds -Wno-address  -flto -DUSING_LTO -Wno-switch -D_CRT_SECURE_NO_WARNINGS /w")
        SET(MBEDTLS_FLAGS "")
        SET(OPENSSL_FLAGS "/FIBase.h")
        SET(CMOCKA_FLAGS " -Wpedantic -Wall -Wshadow -Wmissing-prototypes -Wcast-align -Werror=address -Wstrict-prototypes -Werror=strict-prototypes -Wwrite-strings -Werror=write-strings -Werror-implicit-function-declaration -Wpointer-arith -Werror=pointer-arith -Wdeclaration-after-statement -Werror=declaration-after-statement -Wreturn-type -Werror=return-type -Wuninitialized -Werror=uninitialized -Werror=strict-overflow -Wstrict-overflow=2 -Wno-format-zero-length -Wmissing-field-initializers -Wformat-security -Werror=format-security -Wformat")
       
        SET(CMAKE_C_COMPILER_AR llvm-lib.exe)

        SET(CMAKE_LINKER lld-link.exe)
        SET(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /IGNORE:4086 /MLLVM:-exception-model=wineh /lldmap /OPT:REF")
          
        if(ARCH STREQUAL "X64")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64 /LIBPATH:'%VCToolsInstallDir%lib/x64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
        elseif(ARCH STREQUAL "Ia32")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386 /LIBPATH:'%VCToolsInstallDir%lib/x86' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
        endif()

        SET(CMAKE_C_FLAGS_RELEASE     "-Oz")  
        SET(CMAKE_C_FLAGS_DEBUG       "-O0 -gcodeview")

        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG:GHASH")

        if(ARCH STREQUAL "X64")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
        elseif(ARCH STREQUAL "Ia32")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -march=i586")
        endif()

        SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")

    else()
        SET(CMAKE_C_FLAGS "/nologo /WX /GS- /W4 /Gs32768 /D UNICODE /Gy /EHs-c- /GR- /GF /Z7 /Gw /Oy- /D _CRT_SECURE_NO_WARNINGS /wd4063")
        SET(MBEDTLS_FLAGS "/wd4244 /wd4132 /wd4245 /wd4310 /wd4701 /wd4127")
        SET(OPENSSL_FLAGS "/FIBase.h /wd4090 /wd4132 /wd4244 /wd4245 /wd4267 /wd4306 /wd4310 /wd4700 /wd4389 /wd4702 /wd4706 /wd4819 /wd4013")
        SET(CMOCKA_FLAGS "/wd4204 /wd4133 /wd4267 /wd4701 /wd4702 /wd4703 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES=1 /D _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT=1 /D _CRT_NONSTDC_NO_WARNINGS=1 /D _CRT_SECURE_NO_WARNINGS=1")
                
        SET(CMAKE_STATIC_LINKER_FLAGS "/NOLOGO /LTCG")

        SET(CMAKE_EXE_LINKER_FLAGS "/NOLOGO /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmt.lib /IGNORE:4086 /MAP /OPT:REF")

        SET(CMAKE_C_FLAGS_RELEASE     "/GL /O1b2s")  
        SET(CMAKE_C_FLAGS_DEBUG       "/Od")
        SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG")
        SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "/DEBUG")
    
        if(ARCH STREQUAL "X64")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:AMD64")
        elseif(ARCH STREQUAL "Ia32")
            SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MACHINE:I386")
        endif()
        SET(CMAKE_C_STANDARD_LIBRARIES "Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib ws2_32.lib")
    
    endif()
endif()

if(TOOLCHAIN STREQUAL "VS2015")
    if(ARCH STREQUAL "X64")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCINSTALLDIR%Lib/AMD64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
    elseif(ARCH STREQUAL "Ia32")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCINSTALLDIR%Lib' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
    endif()
elseif(TOOLCHAIN STREQUAL "VS2019")
    if(ARCH STREQUAL "X64")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCToolsInstallDir%lib/x64' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x64' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x64'")
    elseif(ARCH STREQUAL "Ia32")
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LIBPATH:'%VCToolsInstallDir%lib/x86' /LIBPATH:'%UniversalCRTSdkDir%lib/%UCRTVersion%/ucrt/x86' /LIBPATH:'%WindowsSdkDir%lib/%WindowsSDKLibVersion%/um/x86'")
    endif()
endif()
    
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_CUSTOM_TARGET(CopyTestKey)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    ADD_CUSTOM_COMMAND(TARGET CopyTestKey
                    PRE_BUILD
                    COMMAND cp -r -f ${PROJECT_SOURCE_DIR}/OsTest/TestKey/* ${EXECUTABLE_OUTPUT_PATH})
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    STRING(REPLACE "/" "\\" SRC ${PROJECT_SOURCE_DIR}/OsTest/TestKey/*)
    STRING(REPLACE "/" "\\" DEST ${EXECUTABLE_OUTPUT_PATH})
    
    ADD_CUSTOM_COMMAND(TARGET CopyTestKey
                       PRE_BUILD
                       COMMAND xcopy /y /s ${SRC} ${DEST})
endif()

if(CRYPTO STREQUAL "MbedTls")
    SUBDIRS(OsStub/BaseCryptLibMbedTls
            OsStub/MbedTlsLib
    )
elseif(CRYPTO STREQUAL "Openssl")
    SUBDIRS(OsStub/BaseCryptLibOpenssl
            OsStub/OpensslLib
    )
endif()

if(TESTTYPE STREQUAL "OsTest") 
    SUBDIRS(Library/SpdmLib/SpdmCommonLib
            Library/SpdmLib/SpdmRequesterLib
            Library/SpdmLib/SpdmResponderLib
            Library/SpdmLib/SpdmSecuredMessageLib
            Library/SpdmLib/SpdmTransportMctpLib
            OsStub/BaseMemoryLib
            OsStub/DebugLib
            OsStub/MemoryAllocationLib
    )
            
    SUBDIRS(OsTest/SpdmRequesterTest
            OsTest/SpdmResponderTest
    )
       
elseif(TESTTYPE STREQUAL "UnitTest")
    SUBDIRS(Library/SpdmLib/SpdmCommonLib
            Library/SpdmLib/SpdmRequesterLib
            Library/SpdmLib/SpdmResponderLib
            Library/SpdmLib/SpdmSecuredMessageLib
            OsStub/BaseMemoryLib
            OsStub/DebugLib
            OsStub/MemoryAllocationLib
            UnitTest/SpdmTransportTestLib
            UnitTest/CmockaLib
    )
            
    SUBDIRS(UnitTest/TestSpdmRequester
            UnitTest/TestSpdmResponder
    )
# elseif(TESTTYPE STREQUAL "UnitFuzzing")
    # SUBDIRS(Library/SpdmLib/SpdmCommonLib
            # Library/SpdmLib/SpdmRequesterLib
            # Library/SpdmLib/SpdmResponderLib
            # Library/SpdmLib/SpdmEncodingLib
            # OsStub/BaseMemoryLib
            # OsStub/DebugLib
            # OsStub/MemoryAllocationLib
    # )
    
    # SUBDIRS(UnitFuzzing/TestSpdmRequesterGetVersion
            # UnitFuzzing/TestSpdmResponderVersion
    # )
endif()

   




