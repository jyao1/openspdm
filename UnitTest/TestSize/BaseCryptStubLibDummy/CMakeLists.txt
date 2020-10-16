cmake_minimum_required(VERSION 2.6)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-incompatible-pointer-types -Wno-pointer-sign")
endif()

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/OsStub/Include
)

SET(src_BaseCryptStubLibDummy
    RandDummy.c
    TimeClockDummy.c
)

ADD_LIBRARY(BaseCryptStubLibDummy STATIC ${src_BaseCryptStubLibDummy})
