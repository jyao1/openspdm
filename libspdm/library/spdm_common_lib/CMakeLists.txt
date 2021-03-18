cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_common_lib 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_spdm_common_lib
    context_data.c
    context_data_session.c
    crypto_service.c
    crypto_service_session.c
    opaque_data.c
    support.c
)

ADD_LIBRARY(spdm_common_lib STATIC ${src_spdm_common_lib})
