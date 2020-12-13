cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmTransportPciDoeLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmTransportPciDoeLib
    SpdmTransportCommonLib.c
    SpdmTransportPciDoeLib.c
)

ADD_LIBRARY(SpdmTransportPciDoeLib STATIC ${src_SpdmTransportPciDoeLib})
