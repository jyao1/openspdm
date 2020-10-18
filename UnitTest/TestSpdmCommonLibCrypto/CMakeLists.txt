cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmRequester
                    ${PROJECT_SOURCE_DIR}/OsTest/SpdmTestCommon
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include/cmockery
                    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon
)

SET(src_TestSpdmCommonLibCrypto
    TestSpdmCommonLibCrypto.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmUnitTestCommon.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestKey.c
    ${PROJECT_SOURCE_DIR}/UnitTest/SpdmUnitTestCommon/SpdmTestSupport.c
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(TestSpdmCommonLibCrypto_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/libBaseMemoryLib.a
        ${LIBRARY_OUTPUT_PATH}/libDebugLib.a
        ${LIBRARY_OUTPUT_PATH}/libSpdmCommonLib.a
        ${LIBRARY_OUTPUT_PATH}/lib${CRYPTO}Lib.a
        ${LIBRARY_OUTPUT_PATH}/libBaseCryptLib${CRYPTO}.a
        ${LIBRARY_OUTPUT_PATH}/libRngLib.a
        ${LIBRARY_OUTPUT_PATH}/libMemoryAllocationLib.a
        ${LIBRARY_OUTPUT_PATH}/libCmockaLib.a
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(TestSpdmCommonLibCrypto_LIBRARY
        ${LIBRARY_OUTPUT_PATH}/BaseMemoryLib.lib
        ${LIBRARY_OUTPUT_PATH}/DebugLib.lib
        ${LIBRARY_OUTPUT_PATH}/SpdmCommonLib.lib
        ${LIBRARY_OUTPUT_PATH}/${CRYPTO}Lib.lib
        ${LIBRARY_OUTPUT_PATH}/BaseCryptLib${CRYPTO}.lib
        ${LIBRARY_OUTPUT_PATH}/RngLib.lib
        ${LIBRARY_OUTPUT_PATH}/MemoryAllocationLib.lib
        ${LIBRARY_OUTPUT_PATH}/CmockaLib.lib
    )
endif()

ADD_EXECUTABLE(TestSpdmCommonLibCrypto ${src_TestSpdmCommonLibCrypto})

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    TARGET_LINK_LIBRARIES(TestSpdmCommonLibCrypto -Wl,--start-group ${TestSpdmCommonLibCrypto_LIBRARY} -Wl,--end-group)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    TARGET_LINK_LIBRARIES(TestSpdmCommonLibCrypto ${TestSpdmCommonLibCrypto_LIBRARY})
endif()

