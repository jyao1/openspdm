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

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(SpdmResponderTest_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
        ${LIBRARY_OUTPUT_PATH}/libDebugLib.a  
        ${LIBRARY_OUTPUT_PATH}/libSpdmResponderLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a
        ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
        ${LIBRARY_OUTPUT_PATH}/libRngLib.a
        ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmSecuredMessageLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmTransportMctpLib.a   
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(SpdmResponderTest_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/BaseMemoryLib.lib
        ${LIBRARY_OUTPUT_PATH}/DebugLib.lib  
        ${LIBRARY_OUTPUT_PATH}/SpdmResponderLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmCommonLib.lib
        ${LIBRARY_OUTPUT_PATH}/${CRYPTO}Lib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptLib${CRYPTO}.lib   
        ${LIBRARY_OUTPUT_PATH}/RngLib.lib
        ${LIBRARY_OUTPUT_PATH}/MemoryAllocationLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmSecuredMessageLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmTransportMctpLib.lib 
    )
endif()

ADD_EXECUTABLE(SpdmResponderTest ${src_SpdmResponderTest})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_LINK_LIBRARIES(SpdmResponderTest -Wl,--start-group ${SpdmResponderTest_LIBRARY} -Wl,--end-group)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    TARGET_LINK_LIBRARIES(SpdmResponderTest ${SpdmResponderTest_LIBRARY})
endif()
