cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/os_stub/spdm_device_secret_lib_null
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_spdm_device_secret_lib_null
    lib.c
)

ADD_LIBRARY(spdm_device_secret_lib_null STATIC ${src_spdm_device_secret_lib_null})
