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

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(SpdmRequesterTest_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
        ${LIBRARY_OUTPUT_PATH}/libDebugLib.a  
        ${LIBRARY_OUTPUT_PATH}/libSpdmRequesterLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a
        ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
        ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmSecuredMessageLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmTransportMctpLib.a    
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(SpdmRequesterTest_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/BaseMemoryLib.lib
        ${LIBRARY_OUTPUT_PATH}/DebugLib.lib  
        ${LIBRARY_OUTPUT_PATH}/SpdmRequesterLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmCommonLib.lib
        ${LIBRARY_OUTPUT_PATH}/${CRYPTO}Lib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptLib${CRYPTO}.lib   
        ${LIBRARY_OUTPUT_PATH}/MemoryAllocationLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmSecuredMessageLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmTransportMctpLib.lib 
    )
endif()

ADD_EXECUTABLE(SpdmRequesterTest ${src_SpdmRequesterTest})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_LINK_LIBRARIES(SpdmRequesterTest -Wl,--start-group ${SpdmRequesterTest_LIBRARY} -Wl,--end-group)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    TARGET_LINK_LIBRARIES(SpdmRequesterTest ${SpdmRequesterTest_LIBRARY})
endif()