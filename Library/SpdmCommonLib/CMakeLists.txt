cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmCommonLib
    SpdmCommonLibContextData.c
    SpdmCommonLibContextDataSession.c
    SpdmCommonLibCryptoService.c
    SpdmCommonLibCryptoServiceSession.c
    SpdmCommonLibOpaqueData.c
    SpdmCommonLibSupport.c
)

ADD_LIBRARY(SpdmCommonLib STATIC ${src_SpdmCommonLib})
