cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/unit_test/test_crypt
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/include
)

SET(src_test_crypt
    test_crypt.c
    hash_verify.c
    hmac_verify.c
    aead_verify.c
    rsa_verify.c
    rsa_verify2.c
    dh_verify.c
    ec_verify.c
    ec_verify2.c
    ecd_verify.c
    ecd_verify2.c
    ecx_verify.c
    sm2_verify.c
    sm2_verify2.c
    rand_verify.c
    x509_verify.c
    os_support.c
)

SET(test_crypt_LIBRARY
    memlib
    debuglib
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    malloclib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_crypt
                   ${src_test_crypt}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
    )
else()
    ADD_EXECUTABLE(test_crypt ${src_test_crypt})
    TARGET_LINK_LIBRARIES(test_crypt ${test_crypt_LIBRARY})
endif()

