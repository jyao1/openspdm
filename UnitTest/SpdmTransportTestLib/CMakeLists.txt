cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/UnitTest/SpdmTransportTestLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
                    ${PROJECT_SOURCE_DIR}/UnitTest/Include
)

SET(src_SpdmTransportTestLib
    SpdmTransportCommonLib.c
    SpdmTransportTestLib.c
)

ADD_LIBRARY(SpdmTransportTestLib STATIC ${src_SpdmTransportTestLib})
