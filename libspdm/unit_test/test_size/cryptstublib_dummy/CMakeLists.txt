cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types -Wno-pointer-sign")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/os_stub/include
)

SET(src_cryptstublib_dummy
    rand_dummy.c
    timeclock_dummy.c
)

ADD_LIBRARY(cryptstublib_dummy STATIC ${src_cryptstublib_dummy})
