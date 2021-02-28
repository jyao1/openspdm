cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmResponderEmu
                    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon
                    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmDeviceSecretLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
)

SET(src_SpdmResponderTest
    SpdmResponder.c
    SpdmResponderSession.c
    SpdmResponderEmu.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmu.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmuCommand.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmuKey.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmuNvStorage.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmuPcap.c
    ${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmEmuCommon/SpdmEmuSupport.c
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
    SpdmCryptLib
    SpdmSecuredMessageLib
    SpdmTransportMctpLib
    SpdmTransportPciDoeLib
    SpdmDeviceSecretLib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(SpdmResponderEmu
                   ${src_SpdmResponderTest}
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
                   $<TARGET_OBJECTS:SpdmTransportMctpLib>
                   $<TARGET_OBJECTS:SpdmTransportPciDoeLib>
                   $<TARGET_OBJECTS:SpdmDeviceSecretLib>
    ) 
else()
    ADD_EXECUTABLE(SpdmResponderEmu ${src_SpdmResponderTest})
    TARGET_LINK_LIBRARIES(SpdmResponderEmu ${SpdmResponderTest_LIBRARY})
endif()
