cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_rnglib_null
    rnglib.c
)

ADD_LIBRARY(rnglib_null STATIC ${src_rnglib_null})
