cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmResponder
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmResponderLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmSecuredMessageLib
                    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmDeviceSecretLib
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include/cmockery
                    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon
)

SET(src_TestSpdmResponder
    TestSpdmResponder.c
    TestSpdmResponderVersion.c
    TestSpdmResponderCapability.c
    TestSpdmResponderAlgorithm.c
    TestSpdmResponderDigest.c
    TestSpdmResponderCertificate.c
    TestSpdmResponderChallengeAuth.c
    TestSpdmResponderMeasurement.c
    TestSpdmResponderKeyExchange.c
    TestSpdmResponderFinish.c
    TestSpdmResponderPskExchange.c
    TestSpdmResponderPskFinish.c
    TestSpdmResponderHeartbeat.c
    TestSpdmResponderEndSession.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmUnitTestCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestSupport.c
)

SET(TestSpdmResponder_LIBRARY
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
    SpdmDeviceSecretLib
    SpdmTransportTestLib
    CmockaLib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(TestSpdmResponder  
                   ${src_TestSpdmResponder}
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
                   $<TARGET_OBJECTS:SpdmDeviceSecretLib>
                   $<TARGET_OBJECTS:SpdmTransportTestLib>
                   $<TARGET_OBJECTS:CmockaLib>
    ) 
else()
    ADD_EXECUTABLE(TestSpdmResponder ${src_TestSpdmResponder})
    TARGET_LINK_LIBRARIES(TestSpdmResponder ${TestSpdmResponder_LIBRARY})
endif()


