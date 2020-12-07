

#ifndef __SPDM_H
#define __SPDM_H

#if defined(__cplusplus)
extern "C"
{
#endif

#include "EverParse.h"

    static inline BOOLEAN
    EverParseIsError(uint64_t positionOrError);

    static inline uint64_t
    EverParseMaybeSetErrorCode(
        uint64_t positionOrError,
        uint64_t positionAtError,
        uint64_t code);

    static inline uint64_t
    EverParseCheckConstraintOkWithFieldId(
        BOOLEAN ok,
        uint64_t startPosition,
        uint64_t endPosition,
        uint64_t fieldId);

    uint64_t
    SpdmValidateGetVersionRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateVersionNumberEntry(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulVersionResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateRequesterFlag(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateGetCpabilitiesRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateResponderFlag(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulCpabilitiesResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateExtendedAlgorithmField(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateDhe(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateAead(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateReqBaseAsymAlg(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateKeySchedule(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateNegotiateAlgorithmsRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulAlgorithmsResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetDigestsRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulDigestsResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetCertificateRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulCertificateResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateChallengeRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateChallengeAuthResponseAttribute(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulChallengeAuthResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetMeasurementsRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulMeasurementsResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateErrorResponseMessage(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateResponsenotreadyExtendedErrorData(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateExtenderrordataForVendor(
        uint32_t Variable,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateRespondIfReadyRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateVendorDefinedRequestRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateVendorDefinedResponseResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeyExchangeRequestMessage(
        uint32_t D,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulKeyExchangeRspResponseMessage(
        uint32_t D,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateFinishRequestMessage(InputBuffer Input, uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulFinishResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidatePskExchangeRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidatePskExchangeRspResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidatePskFinishRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateSuccessfulPskFinishRspResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateHeartbeatRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateHeartbeatAckResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeyUpdateRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateKeyUpdateAckResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateGetEncapsulatedRequestRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEncapsulatedRequestResponseMessage(
        uint32_t Variable,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateDeliverEncapsulatedResponseRequestMessage(
        uint32_t Variable,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEncapsulatedResponseAckResponseMessage(
        uint32_t Variable,
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEndSessionRequestMessage(
        InputBuffer Input,
        uint64_t StartPosition);

    uint64_t
    SpdmValidateEndSessionAckResponseMessage(
        InputBuffer Input,
        uint64_t StartPosition);

#if defined(__cplusplus)
}
#endif

#define __SPDM_H_DEFINED
#endif
