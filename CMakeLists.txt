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

SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_CUSTOM_TARGET(CopyTestKey)

ADD_CUSTOM_COMMAND(TARGET CopyTestKey
                   PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/OsTest/TestKey/* ${EXECUTABLE_OUTPUT_PATH})
                
ADD_CUSTOM_COMMAND(TARGET CopyTestKey 
                   PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/OsTest/TestKey/test ${EXECUTABLE_OUTPUT_PATH}/test)


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

   




