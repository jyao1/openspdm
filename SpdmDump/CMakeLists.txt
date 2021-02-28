cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/SpdmDump
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
)

SET(src_SpdmDump
    SpdmDump.c
    SpdmDumpPcap.c
    SpdmDumpSupport.c
    Spdm/SpdmDumpSpdm.c
    Spdm/SpdmDumpSecuredSpdm.c
    Spdm/SpdmDumpSession.c
    Mctp/MctpDump.c
    Mctp/Pldm/MctpDumpPldm.c
    Pci/PciDoeDump.c
    Pci/SpdmDumpVendorPci.c
    Pci/PciDoe/PciDoeDumpDoe.c
    Pci/PciIdeKm/SpdmDumpPciIdeKm.c
)

SET(SpdmDump_LIBRARY
    BaseMemoryLib
    DebugLibNull
    SpdmCommonLib
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}
    MemoryAllocationLib
    SpdmCryptLib
    SpdmSecuredMessageLib
    SpdmTransportMctpLib
    SpdmTransportPciDoeLib
    SpdmDeviceSecretLibNull
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(SpdmDump
                   ${src_SpdmDump}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLibNull>
                   $<TARGET_OBJECTS:SpdmCommonLib>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLib>
                   $<TARGET_OBJECTS:SpdmCryptLib>
                   $<TARGET_OBJECTS:SpdmSecuredMessageLib>
                   $<TARGET_OBJECTS:SpdmTransportMctpLib>
                   $<TARGET_OBJECTS:SpdmTransportPciDoeLib>
                   $<TARGET_OBJECTS:SpdmDeviceSecretLibNull>
    ) 
else()
    ADD_EXECUTABLE(SpdmDump ${src_SpdmDump})
    TARGET_LINK_LIBRARIES(SpdmDump ${SpdmDump_LIBRARY})
endif()
