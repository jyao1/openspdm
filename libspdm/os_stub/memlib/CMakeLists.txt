cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
)

SET(src_memlib
    compare_mem.c
    copy_mem.c
    set_mem.c
    zero_mem.c
)

ADD_LIBRARY(memlib STATIC ${src_memlib})
