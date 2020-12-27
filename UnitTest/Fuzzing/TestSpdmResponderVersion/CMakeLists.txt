cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/TestSpdmResponderVersion
                        ${PROJECT_SOURCE_DIR}/Include
                        ${PROJECT_SOURCE_DIR}/Include/Hal
                        ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                        ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                        ${PROJECT_SOURCE_DIR}/Library/SpdmResponderLib
                        ${PROJECT_SOURCE_DIR}/UnitTest/Include
                        ${PROJECT_SOURCE_DIR}/UnitTest/Fuzzing/SpdmUnitFuzzingCommon
)

if(TOOLCHAIN STREQUAL "KLEE")
    INCLUDE_DIRECTORIES($ENV{KLEE_SRC_PATH}/include)
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
    SpdmCryptLib
    SpdmSecuredMessageLib
    SpdmTransportTestLib
    SpdmDeviceSecretLibNull
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(TestSpdmResponderVersion
                   ${src_TestSpdmResponderVersion}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLib>
                   $<TARGET_OBJECTS:SpdmResponderLib>
                   $<TARGET_OBJECTS:SpdmCommonLib>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLib>
                   $<TARGET_OBJECTS:SpdmCryptLib>
                   $<TARGET_OBJECTS:SpdmSecuredMessageLib>
                   $<TARGET_OBJECTS:SpdmTransportTestLib>
                   $<TARGET_OBJECTS:SpdmDeviceSecretLibNull>
    ) 
else()
    ADD_EXECUTABLE(TestSpdmResponderVersion ${src_TestSpdmResponderVersion})
    TARGET_LINK_LIBRARIES(TestSpdmResponderVersion ${TestSpdmResponderVersion_LIBRARY})
endif()
