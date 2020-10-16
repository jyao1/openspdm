cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_MemoryAllocationLibNull
    MemoryAllocationLib.c
)

ADD_LIBRARY(MemoryAllocationLibNull STATIC ${src_MemoryAllocationLibNull})
