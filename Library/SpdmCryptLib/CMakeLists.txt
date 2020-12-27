cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmCryptLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmCryptLib
    SpdmCryptLib.c
)

ADD_LIBRARY(SpdmCryptLib STATIC ${src_SpdmCryptLib})
