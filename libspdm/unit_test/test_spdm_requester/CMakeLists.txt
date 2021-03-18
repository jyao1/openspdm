cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/unit_test/test_spdm_requester
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_common_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_requester_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_secured_message_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/spdm_device_secret_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include/cmockery
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common
)

SET(src_test_spdm_requester
    test_spdm_requester.c
    get_version.c
    get_capabilities.c
    negotiate_algorithms.c
    get_digests.c
    get_certificate.c
    challenge.c
    get_measurements.c
    key_exchange.c
    finish.c
    psk_exchange.c
    psk_finish.c
    heartbeat.c
    end_session.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/common.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/algo.c
    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_unit_test_common/support.c
)

SET(test_spdm_requester_LIBRARY
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
    spdm_device_secret_lib
    spdm_transport_test_lib
    cmockalib
)

if((TOOLCHAIN STREQUAL "KLEE") OR (TOOLCHAIN STREQUAL "CBMC"))
    ADD_EXECUTABLE(test_spdm_requester
                   ${src_test_spdm_requester}
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
                   $<TARGET_OBJECTS:spdm_device_secret_lib>
                   $<TARGET_OBJECTS:spdm_transport_test_lib>
                   $<TARGET_OBJECTS:cmockalib>
    )
else()
    ADD_EXECUTABLE(test_spdm_requester ${src_test_spdm_requester})
    TARGET_LINK_LIBRARIES(test_spdm_requester ${test_spdm_requester_LIBRARY})
endif()


