cmake_minimum_required(VERSION 2.6)

if(TOOLCHAIN STREQUAL "KLEE")
    INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/TestSpdmRequesterGetVersion
                        ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                        ${PROJECT_SOURCE_DIR}/Include
                        ${PROJECT_SOURCE_DIR}/Include/Hal 
                        ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                        ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                        ${PROJECT_SOURCE_DIR}/Library/SpdmRequesterLib
                        ${PROJECT_SOURCE_DIR}/UnitTest/Include
                        ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon
                        $ENV{KLEE_SRC_PATH}/include
    )
else()
    INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/TestSpdmRequesterGetVersion
                        ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                        ${PROJECT_SOURCE_DIR}/Include
                        ${PROJECT_SOURCE_DIR}/Include/Hal 
                        ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                        ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                        ${PROJECT_SOURCE_DIR}/Library/SpdmRequesterLib
                        ${PROJECT_SOURCE_DIR}/UnitTest/Include
                        ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon              
    )
endif()

SET(src_TestSpdmRequesterGetVersion
    TestSpdmRequesterGetVersion.c
    ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon/SpdmUnitFuzzingCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon/ToolChainHarness.c
)

SET(TestSpdmRequesterGetVersion_LIBRARY
    BaseMemoryLib
    DebugLib  
    SpdmRequesterLib
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}   
    MemoryAllocationLib
    SpdmSecuredMessageLib
    SpdmTransportTestLib 
)

ADD_EXECUTABLE(TestSpdmRequesterGetVersion ${src_TestSpdmRequesterGetVersion})

if(TOOLCHAIN STREQUAL "KLEE")
    if(CRYPTO STREQUAL "MbedTls")
        TARGET_LINK_LIBRARIES(TestSpdmRequesterGetVersion
                              ${BaseMemoryLib_OBJECTS}
                              ${DebugLib_OBJECTS}
                              ${SpdmRequesterLib_OBJECTS}
                              ${SpdmSecuredMessageLib_OBJECTS}
                              ${MbedTlsLib_OBJECTS}
                              ${RngLib_OBJECTS}
                              ${SpdmCommonLib_OBJECTS}
                              ${BaseCryptLibMbedTls_OBJECTS}
                              ${MemoryAllocationLib_OBJECTS}
                              ${SpdmTransportTestLib_OBJECTS}
        )
    else()
        TARGET_LINK_LIBRARIES(TestSpdmRequesterGetVersion
                              ${BaseMemoryLib_OBJECTS}
                              ${DebugLib_OBJECTS}
                              ${SpdmRequesterLib_OBJECTS}
                              ${SpdmSecuredMessageLib_OBJECTS}
                              ${OpensslLib_OBJECTS}
                              ${RngLib_OBJECTS}
                              ${SpdmCommonLib_OBJECTS}
                              ${BaseCryptLibOpenssl_OBJECTS}
                              ${MemoryAllocationLib_OBJECTS}
                              ${SpdmTransportTestLib_OBJECTS}
        )
    endif()
else()
    TARGET_LINK_LIBRARIES(TestSpdmRequesterGetVersion ${TestSpdmRequesterGetVersion_LIBRARY})
endif()
