cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/OsTest/SpdmResponderTest
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}                 
)

SET(src_SpdmResponderTest
    SpdmResponder.c
    SpdmResponderMeasurement.c
    SpdmResponderTest.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestCommand.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestSupport.c
)

SET(SpdmResponderTest_LIBRARY
    BaseMemoryLib
    DebugLib  
    SpdmResponderLib
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}   
    MemoryAllocationLib
    SpdmSecuredMessageLib
    SpdmTransportMctpLib 
)

ADD_EXECUTABLE(SpdmResponderTest ${src_SpdmResponderTest})

TARGET_LINK_LIBRARIES(SpdmResponderTest ${SpdmResponderTest_LIBRARY})
