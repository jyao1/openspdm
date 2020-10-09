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
    ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
    ${LIBRARY_OUTPUT_PATH}/libDebugLib.a  
    ${LIBRARY_OUTPUT_PATH}/libSpdmResponderLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a
    ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
    ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
    ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmSecuredMessageLib.a
    ${LIBRARY_OUTPUT_PATH}/libSpdmTransportMctpLib.a   
)

ADD_EXECUTABLE(SpdmResponderTest ${src_SpdmResponderTest})

TARGET_LINK_LIBRARIES(SpdmResponderTest -Wl,--start-group ${SpdmResponderTest_LIBRARY} -Wl,--end-group)

