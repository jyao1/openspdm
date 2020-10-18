cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -Wl,-n,-q,--gc-sections -Wl,--entry,ModuleEntryPoint")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_EXE_LINKER_FLAGS "/DLL /ENTRY:ModuleEntryPoint /NOLOGO /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER /NODEFAULTLIB /IGNORE:4086 /MAP /OPT:REF")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSizeOfSpdmResponder
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include                    
)

SET(src_TestSizeOfSpdmResponder
    SpdmResponderInit.c
    SpdmResponderMain.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(TestSizeOfSpdmResponder_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
        ${LIBRARY_OUTPUT_PATH}/libDebugLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmResponderLib.a    
        ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a 
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptStubLibDummy.a
        ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
        ${LIBRARY_OUTPUT_PATH}/libRngLib.a
        ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLibNull.a
        ${LIBRARY_OUTPUT_PATH}/libIntrinsicLib.a    
        ${LIBRARY_OUTPUT_PATH}/libSpdmSecuredMessageLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmTransportMctpLib.a 
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(TestSizeOfSpdmResponder_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/BaseMemoryLib.lib
        ${LIBRARY_OUTPUT_PATH}/DebugLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmResponderLib.lib    
        ${LIBRARY_OUTPUT_PATH}/SpdmCommonLib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptStubLibDummy.lib
        ${LIBRARY_OUTPUT_PATH}/${CRYPTO}Lib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptLib${CRYPTO}.lib   
        ${LIBRARY_OUTPUT_PATH}/RngLib.lib
        ${LIBRARY_OUTPUT_PATH}/MemoryAllocationLibNull.lib
        ${LIBRARY_OUTPUT_PATH}/IntrinsicLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmSecuredMessageLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmTransportMctpLib.lib 
    )
endif()

ADD_EXECUTABLE(TestSizeOfSpdmResponder ${src_TestSizeOfSpdmResponder})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_LINK_LIBRARIES(TestSizeOfSpdmResponder -Wl,--start-group ${TestSizeOfSpdmResponder_LIBRARY} -Wl,--end-group)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    TARGET_LINK_LIBRARIES(TestSizeOfSpdmResponder ${TestSizeOfSpdmResponder_LIBRARY})
endif()

