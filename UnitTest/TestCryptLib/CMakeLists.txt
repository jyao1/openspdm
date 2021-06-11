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
    EcxVerify.c
    EdVerify.c
    EdVerify2.c
    RandVerify.c
    Sm2Verify.c
    Sm2Verify2.c
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

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(TestCryptLib 
                   ${src_TestCryptLib}
                   $<TARGET_OBJECTS:BaseMemoryLib>
                   $<TARGET_OBJECTS:DebugLib>
                   $<TARGET_OBJECTS:${CRYPTO}Lib>
                   $<TARGET_OBJECTS:RngLib>
                   $<TARGET_OBJECTS:BaseCryptLib${CRYPTO}>
                   $<TARGET_OBJECTS:MemoryAllocationLib>
    ) 
else()
    ADD_EXECUTABLE(TestCryptLib ${src_TestCryptLib})
    TARGET_LINK_LIBRARIES(TestCryptLib ${TestCryptLib_LIBRARY})
endif()

