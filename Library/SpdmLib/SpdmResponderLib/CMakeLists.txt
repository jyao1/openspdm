cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmResponderLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmLib/SpdmCommonLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmResponderLib
    SpdmResponderLibAlgorithm.c
    SpdmResponderLibCapability.c
    SpdmResponderLibCertificate.c
    SpdmResponderLibChallengeAuth.c
    SpdmResponderLibCommunication.c
    SpdmResponderLibDigest.c
    SpdmResponderLibEncapChallenge.c
    SpdmResponderLibEncapGetCertificate.c
    SpdmResponderLibEncapGetDigest.c
    SpdmResponderLibEncapResponse.c
    SpdmResponderLibEndSession.c
    SpdmResponderLibError.c
    SpdmResponderLibFinish.c
    SpdmResponderLibHandleResponseState.c
    SpdmResponderLibHeartbeat.c
    SpdmResponderLibKeyExchange.c
    SpdmResponderLibKeyUpdate.c
    SpdmResponderLibMeasurement.c
    SpdmResponderLibPskExchange.c
    SpdmResponderLibPskFinish.c
    SpdmResponderLibReceiveSend.c
    SpdmResponderLibRespondIfReady.c
    SpdmResponderLibVersion.c
)

ADD_LIBRARY(SpdmResponderLib STATIC ${src_SpdmResponderLib})