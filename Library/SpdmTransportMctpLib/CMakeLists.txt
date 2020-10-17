cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmTransportMctpLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmTransportMctpLib
    SpdmTransportCommonLib.c
    SpdmTransportMctpLib.c
)

ADD_LIBRARY(SpdmTransportMctpLib STATIC ${src_SpdmTransportMctpLib})
