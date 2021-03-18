cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_common_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/spdm_device_secret_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include/cmockery
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common
)

SET(src_test_spdm_crypt
    test_spdm_crypt.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/common.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/algo.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/support.c
)

SET(test_spdm_crypt_LIBRARY
    memlib
    debuglib
    spdm_crypt_lib
    ${CRYPTO}lib
    cryptlib_${CRYPTO}
    rnglib
    malloclib
    cmockalib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_crypt
                   ${src_test_spdm_crypt}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:cmockalib>
    )
else()
    ADD_EXECUTABLE(test_spdm_crypt ${src_test_spdm_crypt})
    TARGET_LINK_LIBRARIES(test_spdm_crypt ${test_spdm_crypt_LIBRARY})
endif()


