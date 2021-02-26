cmake_minimum_required(VERSION 2.6)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/Library/SpdmRequesterLib
                    ${PROJECT_SOURCE_DIR}/Library/SpdmCommonLib 
                    ${PROJECT_SOURCE_DIR}/Include
                    ${PROJECT_SOURCE_DIR}/Include/Hal 
                    ${PROJECT_SOURCE_DIR}/Include/Hal/${ARCH}
)

SET(src_SpdmRequesterLib
    SpdmRequesterLibChallenge.c
    SpdmRequesterLibCommunication.c
    SpdmRequesterLibEncapCertificate.c
    SpdmRequesterLibEncapChallengeAuth.c
    SpdmRequesterLibEncapDigest.c
    SpdmRequesterLibEncapError.c
    SpdmRequesterLibEncapKeyUpdate.c
    SpdmRequesterLibEncapRequest.c
    SpdmRequesterLibEndSession.c
    SpdmRequesterLibFinish.c
    SpdmRequesterLibGetCapability.c
    SpdmRequesterLibGetCertificate.c
    SpdmRequesterLibGetDigest.c
    SpdmRequesterLibGetMeasurement.c
    SpdmRequesterLibGetVersion.c
    SpdmRequesterLibHandleErrorResponse.c
    SpdmRequesterLibHeartbeat.c
    SpdmRequesterLibKeyExchange.c
    SpdmRequesterLibKeyUpdate.c
    SpdmRequesterLibNegotiateAlgorithm.c
    SpdmRequesterLibPskExchange.c
    SpdmRequesterLibPskFinish.c
    SpdmRequesterLibSendReceive.c
)

ADD_LIBRARY(SpdmRequesterLib STATIC ${src_SpdmRequesterLib})
