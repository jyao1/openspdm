cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmRequester
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH} 
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include                    
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmRequesterLib
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
    SpdmSecuredMessageLib
    SpdmTransportTestLib
    CmockaLib
)

ADD_EXECUTABLE(TestSpdmRequester ${src_TestSpdmRequester})

TARGET_LINK_LIBRARIES(TestSpdmRequester ${TestSpdmRequester_LIBRARY})


