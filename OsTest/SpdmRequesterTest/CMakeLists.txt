cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/OsTest/SpdmRequesterTest
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}                 
)

SET(src_SpdmRequesterTest
    SpdmRequester.c
    SpdmRequesterAuthentication.c
    SpdmRequesterMeasurement.c
    SpdmRequesterSession.c
    SpdmRequesterTest.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestCommand.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestSupport.c
)

SET(SpdmRequesterTest_LIBRARY
    BaseMemoryLib
    DebugLib  
    SpdmRequesterLib
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}   
    MemoryAllocationLib
    SpdmSecuredMessageLib
    SpdmTransportMctpLib 
)

ADD_EXECUTABLE(SpdmRequesterTest ${src_SpdmRequesterTest})

TARGET_LINK_LIBRARIES(SpdmRequesterTest ${SpdmRequesterTest_LIBRARY})
