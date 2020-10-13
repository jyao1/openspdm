cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_SIGNAL_H")
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMOCKA_FLAGS} -DHAVE_VSNPRINTF -DHAVE_SNPRINTF")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include
                    ${PROJECT_SOURCE_DIR}/UnitTest/CmockaLib/cmocka/include/cmockery
)

SET(src_CmockaLib
    cmocka/src/cmocka.c
)

ADD_LIBRARY(CmockaLib STATIC ${src_CmockaLib})
