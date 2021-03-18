cmake_minimum_required(VERSION 2.6)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/unit_test/fuzzing/test_spdm_requester_get_version
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_common_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_requester_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/fuzzing/spdm_unit_fuzzing_common
)

if(TOOLCHAIN STREQUAL "KLEE")
    INCLUDE_DIRECTORIES($ENV{KLEE_SRC_PATH}/include)
endif()

SET(src_test_spdm_requester_get_version
    get_version.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/common.c
    ${PROJECT_SOURCE_DIR}/unit_test/fuzzing/spdm_unit_fuzzing_common/toolchain_harness.c
)

SET(test_spdm_requester_get_version_LIBRARY
    memlib
    debuglib
    spdm_requester_lib
    spdm_common_lib
    ${CRYPTO}lib
    rnglib
    cryptlib_${CRYPTO}
    malloclib
    spdm_crypt_lib
    spdm_secured_message_lib
    spdm_transport_test_lib
    spdm_device_secret_lib_null
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_requester_get_version
                   ${src_test_spdm_requester_get_version}
                   $<TARGET_OBJECTS:memlib>
                   $<TARGET_OBJECTS:debuglib>
                   $<TARGET_OBJECTS:spdm_requester_lib>
                   $<TARGET_OBJECTS:spdm_common_lib>
                   $<TARGET_OBJECTS:${CRYPTO}lib>
                   $<TARGET_OBJECTS:rnglib>
                   $<TARGET_OBJECTS:cryptlib_${CRYPTO}>
                   $<TARGET_OBJECTS:malloclib>
                   $<TARGET_OBJECTS:spdm_crypt_lib>
                   $<TARGET_OBJECTS:spdm_secured_message_lib>
                   $<TARGET_OBJECTS:spdm_transport_test_lib>
                   $<TARGET_OBJECTS:spdm_device_secret_lib_null>
    )
else()
    ADD_EXECUTABLE(test_spdm_requester_get_version ${src_test_spdm_requester_get_version})
    TARGET_LINK_LIBRARIES(test_spdm_requester_get_version ${test_spdm_requester_get_version_LIBRARY})
endif()
