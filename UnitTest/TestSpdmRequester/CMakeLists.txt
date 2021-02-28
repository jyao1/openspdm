cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmRequester
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmRequesterLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmSecuredMessageLib
                    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmDeviceSecretLib
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include/cmockery
                    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon
)

SET(src_TestSpdmRequester
    TestSpdmRequester.c
    TestSpdmRequesterGetVersion.c
    TestSpdmRequesterGetCapability.c
    TestSpdmRequesterNegotiateAlgorithm.c
    TestSpdmRequesterGetDigest.c
    TestSpdmRequesterGetCertificate.c
    TestSpdmRequesterChallenge.c
    TestSpdmRequesterGetMeasurement.c
    TestSpdmRequesterKeyExchange.c
    TestSpdmRequesterFinish.c
    TestSpdmRequesterPskExchange.c
    TestSpdmRequesterPskFinish.c
    TestSpdmRequesterHeartbeat.c
    TestSpdmRequesterEndSession.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmUnitTestCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestSupport.c
)

SET(TestSpdmRequester_LIBRARY
    BaseMemoryLib
    DebugLib
    SpdmRequesterLib
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}
    MemoryAllocationLib
    SpdmCryptLib
    SpdmSecuredMessageLib
    SpdmDeviceSecretLib
    SpdmTransportTestLib
    CmockaLib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(TestSpdmRequester  
                   ${src_TestSpdmRequester}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLib>
                   $<TARGET_OBJECTS:SpdmRequesterLib>
                   $<TARGET_OBJECTS:SpdmCommonLib>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLib>
                   $<TARGET_OBJECTS:SpdmCryptLib>
                   $<TARGET_OBJECTS:SpdmSecuredMessageLib>
                   $<TARGET_OBJECTS:SpdmDeviceSecretLib>
                   $<TARGET_OBJECTS:SpdmTransportTestLib>
                   $<TARGET_OBJECTS:CmockaLib>
    ) 
else()
    ADD_EXECUTABLE(TestSpdmRequester ${src_TestSpdmRequester})
    TARGET_LINK_LIBRARIES(TestSpdmRequester ${TestSpdmRequester_LIBRARY})
endif()


