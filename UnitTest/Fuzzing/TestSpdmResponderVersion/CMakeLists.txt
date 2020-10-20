cmake_minimum_required(VERSION 2.6)

if(TOOLCHAIN STREQUAL "KLEE")
    INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/TestSpdmResponderVersion
                        ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                        ${PROJECT_SOURCE_DIR}/Include
                        ${PROJECT_SOURCE_DIR}/Include/Hal 
                        ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                        ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                        ${PROJECT_SOURCE_DIR}/Library/SpdmResponderLib
                        ${PROJECT_SOURCE_DIR}/UnitTest/Include
                        ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon
                        $ENV{KLEE_SRC_PATH}/include
    )
else()
    INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/TestSpdmResponderVersion
                        ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                        ${PROJECT_SOURCE_DIR}/Include
                        ${PROJECT_SOURCE_DIR}/Include/Hal 
                        ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                        ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                        ${PROJECT_SOURCE_DIR}/Library/SpdmResponderLib
                        ${PROJECT_SOURCE_DIR}/UnitTest/Include
                        ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon                 
    )
endif()

SET(src_TestSpdmResponderVersion
    TestSpdmResponderVersion.c
    ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon/SpdmUnitFuzzingCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon/ToolChainHarness.c
)

SET(TestSpdmResponderVersion_LIBRARY
    BaseMemoryLib
    DebugLib  
    SpdmResponderLib
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}   
    MemoryAllocationLib
    SpdmSecuredMessageLib
    SpdmTransportTestLib 
)

ADD_EXECUTABLE(TestSpdmResponderVersion ${src_TestSpdmResponderVersion})

if(TOOLCHAIN STREQUAL "KLEE")
    TARGET_LINK_LIBRARIES(TestSpdmResponderVersion 
                          ${BaseMemoryLib_OBJECTS}
                          ${DebugLib_OBJECTS}
                          ${SpdmResponderLib_OBJECTS}
                          ${SpdmSecuredMessageLib_OBJECTS}
                          ${MbedTlsLib_OBJECTS}
                          ${RngLib_OBJECTS}
                          ${SpdmCommonLib_OBJECTS}
                          ${BaseCryptLibMbedTls_OBJECTS}
                          ${MemoryAllocationLib_OBJECTS}
                          ${SpdmTransportTestLib_OBJECTS}
    )
else()
    TARGET_LINK_LIBRARIES(TestSpdmResponderVersion ${TestSpdmResponderVersion_LIBRARY})
endif()
