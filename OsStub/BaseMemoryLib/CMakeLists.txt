cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_BaseMemoryLib
    CompareMem.c
    CopyMem.c
    SetMem.c
    ZeroMem.c
)

ADD_LIBRARY(BaseMemoryLib STATIC ${src_BaseMemoryLib})
