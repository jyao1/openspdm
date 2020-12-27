cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -Wl,-n,-q,--gc-sections -Wl,--entry,ModuleEntryPoint")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    if(TOOLCHIAN MATCHES "VS")
        SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
    else()
        SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /OPT:REF")
    endif()
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSize/TestSizeOfSpdmResponder
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
)

SET(src_TestSizeOfSpdmResponder
    SpdmResponderInit.c
    SpdmResponderMain.c
)

SET(TestSizeOfSpdmResponder_LIBRARY
    BaseMemoryLib
    DebugLib
    SpdmResponderLib
    SpdmCommonLib
    BaseCryptStubLibDummy
    ${CRYPTO}Lib
    RngLib
    BaseCryptLib${CRYPTO}
    MemoryAllocationLibNull
    SpdmCryptLib
    SpdmSecuredMessageLib
    SpdmTransportMctpLib
    SpdmDeviceSecretLibNull
    IntrinsicLib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(TestSizeOfSpdmResponder
                   ${src_TestSizeOfSpdmResponder}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLib>
                   $<TARGET_OBJECTS:SpdmResponderLib>
                   $<TARGET_OBJECTS:SpdmCommonLib>
                   $<TARGET_OBJECTS:BaseCryptStubLibDummy>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLibNull>
                   $<TARGET_OBJECTS:SpdmCryptLib>
                   $<TARGET_OBJECTS:SpdmSecuredMessageLib>
                   $<TARGET_OBJECTS:SpdmTransportMctpLib>
                   $<TARGET_OBJECTS:SpdmDeviceSecretLibNull>
                   $<TARGET_OBJECTS:IntrinsicLib>
    ) 
else()
    ADD_EXECUTABLE(TestSizeOfSpdmResponder ${src_TestSizeOfSpdmResponder})
    TARGET_LINK_LIBRARIES(TestSizeOfSpdmResponder ${TestSizeOfSpdmResponder_LIBRARY})
endif()


