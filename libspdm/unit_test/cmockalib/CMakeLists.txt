cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_SIGNAL_H")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib
                    ${PROJECT_SOURCE_DIR}/../libspdm/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal 
                    ${PROJECT_SOURCE_DIR}/../libspdm/include/hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/../libspdm/unit_test/cmockalib/cmocka/include/cmockery
)

SET(src_CmockaLib
    cmocka/src/cmocka.c
)

ADD_LIBRARY(cmockalib STATIC ${src_CmockaLib})
