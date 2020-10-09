cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmSecuredMessageLib 
                    ${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmCommonLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmSecuredMessageLib
    SpdmSecuredMessageLib.c
    SpdmSecuredMessageLibOpaqueData.c
)

ADD_LIBRARY(SpdmSecuredMessageLib STATIC ${src_SpdmSecuredMessageLib})
