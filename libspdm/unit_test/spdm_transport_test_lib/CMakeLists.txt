cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/unit_test/spdm_transport_test_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_common_lib
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/include
)

SET(src_spdm_transport_test_lib
    common.c
    test.c
)

ADD_LIBRARY(spdm_transport_test_lib STATIC ${src_spdm_transport_test_lib})
