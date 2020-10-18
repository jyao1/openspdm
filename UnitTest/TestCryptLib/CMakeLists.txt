cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestCryptLib
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include                
)

SET(src_TestCryptLib
    Cryptest.c
    HashVerify.c
    HmacVerify.c
    MacVerify.c
    AeadVerify.c
    RsaVerify.c
    RsaVerify2.c
    DhVerify.c
    EcVerify.c
    EcVerify2.c
    RandVerify.c
    X509Verify.c
    OsSupport.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(TestCryptLib_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
        ${LIBRARY_OUTPUT_PATH}/libDebugLib.a  
        ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a   
        ${LIBRARY_OUTPUT_PATH}/libRngLib.a
        ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(TestCryptLib_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/BaseMemoryLib.lib
        ${LIBRARY_OUTPUT_PATH}/DebugLib.lib
        ${LIBRARY_OUTPUT_PATH}/${CRYPTO}Lib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptLib${CRYPTO}.lib   
        ${LIBRARY_OUTPUT_PATH}/RngLib.lib
        ${LIBRARY_OUTPUT_PATH}/MemoryAllocationLib.lib
    )
endif()

ADD_EXECUTABLE(TestCryptLib ${src_TestCryptLib})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_LINK_LIBRARIES(TestCryptLib -Wl,--start-group  ${TestCryptLib_LIBRARY} -Wl,--end-group)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    TARGET_LINK_LIBRARIES(TestCryptLib ${TestCryptLib_LIBRARY})
endif()
