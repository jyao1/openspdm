cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/OsTest/SpdmRequesterTest
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
)

SET(src_SpdmRequesterTest
    SpdmRequester.c
    SpdmRequesterAuthentication.c
    SpdmRequesterMeasurement.c
    SpdmRequesterSession.c
    SpdmRequesterTest.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestCommand.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon/SpdmTestPcap.c
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
    SpdmTransportPciDoeLib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(SpdmRequesterTest
                   ${src_SpdmRequesterTest}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLib>
                   $<TARGET_OBJECTS:SpdmRequesterLib>
                   $<TARGET_OBJECTS:SpdmCommonLib>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLib>
                   $<TARGET_OBJECTS:SpdmSecuredMessageLib>
                   $<TARGET_OBJECTS:SpdmTransportMctpLib>
                   $<TARGET_OBJECTS:SpdmTransportPciDoeLib>
    ) 
else()
    ADD_EXECUTABLE(SpdmRequesterTest ${src_SpdmRequesterTest})
    TARGET_LINK_LIBRARIES(SpdmRequesterTest ${SpdmRequesterTest_LIBRARY})
endif()
