cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_transport_pcidoe_lib 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_spdm_transport_pcidoe_lib
    common.c
    pcidoe.c
)

ADD_LIBRARY(spdm_transport_pcidoe_lib STATIC ${src_spdm_transport_pcidoe_lib})
