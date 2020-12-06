#include "EverParseEndianness.h"
#ifdef __cplusplus
extern "C"
{
#endif
    BOOLEAN
    SpdmCheckGetVersionRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckVersionNumberEntry(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulVersionResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckRequesterFlag(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckGetCpabilitiesRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckResponderFlag(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulCpabilitiesResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckExtendedAlgorithmField(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckDhe(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckAead(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckReqBaseAsymAlg(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckKeySchedule(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckNegotiateAlgorithmsRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulAlgorithmsResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckGetDigestsRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulDigestsResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckGetCertificateRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulCertificateResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckChallengeRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckChallengeAuthResponseAttribute(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulChallengeAuthResponseMessage(
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckGetMeasurementsRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulMeasurementsResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckErrorResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckResponsenotreadyExtendedErrorData(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckExtenderrordataForVendor(
        uint32_t ___Variable,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckRespondIfReadyRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckVendorDefinedRequestRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckVendorDefinedResponseResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckKeyExchangeRequestMessage(
        uint32_t ___D,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulKeyExchangeRspResponseMessage(
        uint32_t ___D,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckFinishRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulFinishResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckPskExchangeRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckPskExchangeRspResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckPskFinishRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckSuccessfulPskFinishRspResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckHeartbeatRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckHeartbeatAckResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckKeyUpdateRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckKeyUpdateAckResponseMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckGetEncapsulatedRequestRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckEncapsulatedRequestResponseMessage(
        uint32_t ___Variable,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckDeliverEncapsulatedResponseRequestMessage(
        uint32_t ___Variable,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckEncapsulatedResponseAckResponseMessage(
        uint32_t ___Variable,
        uint8_t *base,
        uint32_t len);

    BOOLEAN
    SpdmCheckEndSessionRequestMessage(uint8_t *base, uint32_t len);

    BOOLEAN
    SpdmCheckEndSessionAckResponseMessage(uint8_t *base, uint32_t len);
#ifdef __cplusplus
}
#endif
