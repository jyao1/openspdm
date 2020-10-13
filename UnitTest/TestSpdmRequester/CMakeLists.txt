cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmRequester
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH} 
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include                    
                    ${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmRequesterLib
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
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmUnitTestCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestSupport.c
)

SET(TestSpdmRequester_LIBRARY
    ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
    ${LIBRARY_OUTPUT_PATH}/libDebugLib.a  
    ${LIBRARY_OUTPUT_PATH}/libSpdmRequesterLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a
    ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
    ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
    ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmSecuredMessageLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmTransportTestLib.a 
    ${LIBRARY_OUTPUT_PATH}/libCmockaLib.a
)

ADD_EXECUTABLE(TestSpdmRequester ${src_TestSpdmRequester})

TARGET_LINK_LIBRARIES(TestSpdmRequester -Wl,--start-group ${TestSpdmRequester_LIBRARY} -Wl,--end-group)

