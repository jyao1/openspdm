cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/SpdmEmu/SpdmDeviceSecretLib
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmDeviceSecretLib
    SpdmDeviceSecretLib.c
    SpdmDeviceSecretLibCert.c
)

ADD_LIBRARY(SpdmDeviceSecretLib STATIC ${src_SpdmDeviceSecretLib})
