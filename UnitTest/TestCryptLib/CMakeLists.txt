cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/TestCryptLib
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

SET(TestCryptLib_LIBRARY
    BaseMemoryLib 
    DebugLib 
    ${CRYPTO}Lib 
    RngLib
    BaseCryptLib${CRYPTO}    
    MemoryAllocationLib 
)

ADD_EXECUTABLE(TestCryptLib ${src_TestCryptLib})

TARGET_LINK_LIBRARIES(TestCryptLib ${TestCryptLib_LIBRARY})

