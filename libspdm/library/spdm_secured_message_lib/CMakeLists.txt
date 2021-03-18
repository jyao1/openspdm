cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/library/spdm_secured_message_lib 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_spdm_secured_message_lib
    context_data.c
    encode_decode.c
    key_exchange.c
    session.c
)

ADD_LIBRARY(spdm_secured_message_lib STATIC ${src_spdm_secured_message_lib})
