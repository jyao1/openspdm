cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestSpdmRequester
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

SET(TestSpdmCommonLibCrypto_LIBRARY
    BaseMemoryLib
    DebugLib
    SpdmCommonLib
    ${CRYPTO}Lib
    BaseCryptLib${CRYPTO}
    RngLib
    MemoryAllocationLib
    CmockaLib
)


ADD_EXECUTABLE(TestSpdmCommonLibCrypto ${src_TestSpdmCommonLibCrypto})

TARGET_LINK_LIBRARIES(TestSpdmCommonLibCrypto ${TestSpdmCommonLibCrypto_LIBRARY})


