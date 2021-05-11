/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               Length;
  UINT8                MeasurementSpecificationSel;
  UINT8                Reserved;
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymSel;
  UINT32               BaseHashSel;
  UINT8                Reserved2[12];
  UINT8                ExtAsymSelCount;
  UINT8                ExtHashSelCount;
  UINT16               Reserved3;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_ALGORITHMS_RESPONSE_MINE;
#pragma pack()

UINT32 mHashPriorityTable[] = {
#if OPENSPDM_SHA512_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
#endif
#if OPENSPDM_SHA384_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
#endif
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
#endif
};

UINT32 mAsymPriorityTable[] = {
#if OPENSPDM_ECDSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
#endif
#if OPENSPDM_RSA_PSS_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
#endif
#if OPENSPDM_RSA_SSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
#endif
};

UINT32 mReqAsymPriorityTable[] = {
#if OPENSPDM_RSA_PSS_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
#endif
#if OPENSPDM_RSA_SSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
#endif
#if OPENSPDM_ECDSA_SUPPORT == 1
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
  SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
#endif
};

UINT32 mDhePriorityTable[] = {
#if OPENSPDM_ECDHE_SUPPORT == 1
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
#endif
#if OPENSPDM_FFDHE_SUPPORT == 1
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
#endif
};

UINT32 mAeadPriorityTable[] = {
#if OPENSPDM_AEAD_GCM_SUPPORT == 1
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
#endif
#if OPENSPDM_AEAD_CHACHA20_POLY1305_SUPPORT == 1
  SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
#endif
};

UINT32 mKeySchedulePriorityTable[] = {
  SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
};

UINT32 mMeasurementHashPriorityTable[] = {
#if OPENSPDM_SHA512_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
#endif
#if OPENSPDM_SHA384_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
#endif
#if OPENSPDM_SHA256_SUPPORT == 1
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
#endif
  SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
};

UINT32 mMeasurementSpecPriorityTable[] = {
  SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,
};

/**
  Select the preferred supproted algorithm according to the PriorityTable.

  @param  PriorityTable                The priority table.
  @param  PriorityTableCount           The count of the priroty table entry.
  @param  LocalAlgo                    Local supported algorithm.
  @param  PeerAlgo                     Peer supported algorithm.

  @return final preferred supported algorithm
**/
UINT32
SpdmPrioritizeAlgorithm (
  IN UINT32            *PriorityTable,
  IN UINTN             PriorityTableCount,
  IN UINT32            LocalAlgo,
  IN UINT32            PeerAlgo
  )
{
  UINT32 CommonAlgo;
  UINTN  Index;

  CommonAlgo = (LocalAlgo & PeerAlgo);
  for (Index = 0; Index < PriorityTableCount; Index++) {
    if ((CommonAlgo & PriorityTable[Index]) != 0) {
      return PriorityTable[Index];
    }
  }

  return 0;
}

/**
  Process the SPDM NEGOTIATE_ALGORITHMS request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetResponseAlgorithm (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST              *SpdmRequest;
  UINTN                                          SpdmRequestSize;
  SPDM_ALGORITHMS_RESPONSE_MINE                  *SpdmResponse;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;
  UINTN                                          Index;
  SPDM_DEVICE_CONTEXT                            *SpdmContext;
  RETURN_STATUS                                  Status;
  UINT32                                         AlgoSize;
  UINT8                                          FixedAlgSize;
  UINT8                                          ExtAlgCount;
  UINT16                                         ExtAlgTotalCount;

  SpdmContext = Context;
  SpdmRequest = Request;
  ExtAlgTotalCount = 0;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (SpdmContext->ConnectionInfo.ConnectionState != SpdmConnectionStateAfterCapabilities) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (RequestSize < sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (RequestSize < sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                    sizeof(UINT32) * SpdmRequest->ExtAsymCount +
                    sizeof(UINT32) * SpdmRequest->ExtHashCount +
                    sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) * SpdmRequest->Header.Param1) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  StructTable = (VOID *)((UINTN)SpdmRequest +
                            sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                            sizeof(UINT32) * SpdmRequest->ExtAsymCount +
                            sizeof(UINT32) * SpdmRequest->ExtHashCount
                            );
  if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    for (Index = 0; Index < SpdmRequest->Header.Param1; Index++) {
      if ((UINTN)SpdmRequest + RequestSize < (UINTN)StructTable) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      if ((UINTN)SpdmRequest + RequestSize - (UINTN)StructTable < sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE)) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      FixedAlgSize = (StructTable->AlgCount >> 4) & 0xF;
      ExtAlgCount = StructTable->AlgCount & 0xF;
      ExtAlgTotalCount += ExtAlgCount;
      if (FixedAlgSize != 2) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      if ((UINTN)SpdmRequest + RequestSize - (UINTN)StructTable - sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) < sizeof(UINT32) * ExtAlgCount) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
    }
  }
  ExtAlgTotalCount += (SpdmRequest->ExtAsymCount + SpdmRequest->ExtHashCount);
  // Algorithm count check and message size check
  if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    if (ExtAlgTotalCount>0x14){
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmRequest->Length>0x80){
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (ExtAlgTotalCount>0x08){
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmRequest->Length>0x40){
      return RETURN_DEVICE_ERROR;
    }
  }
  RequestSize = (UINTN)StructTable - (UINTN)SpdmRequest;
  if (RequestSize != SpdmRequest->Length) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmRequestSize = RequestSize;

  //
  // Cache
  //
  Status = SpdmAppendMessageA (SpdmContext, SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (*ResponseSize >= sizeof(SPDM_ALGORITHMS_RESPONSE_MINE));
  *ResponseSize = sizeof(SPDM_ALGORITHMS_RESPONSE_MINE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmResponse->Header.Param1 = 4; // Number of Algorithms Structure Tables
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse->Header.Param1 = 0;
    *ResponseSize = sizeof(SPDM_ALGORITHMS_RESPONSE_MINE) - sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) * 4;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_ALGORITHMS;
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->Length = (UINT16)*ResponseSize;

  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = SpdmRequest->MeasurementSpecification;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmRequest->BaseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmRequest->BaseHashAlgo;
  if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    StructTable = (VOID *)((UINTN)SpdmRequest +
                            sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                            sizeof(UINT32) * SpdmRequest->ExtAsymCount +
                            sizeof(UINT32) * SpdmRequest->ExtHashCount
                            );
    for (Index = 0; Index < SpdmRequest->Header.Param1; Index++) {
      switch (StructTable->AlgType) {
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        SpdmContext->ConnectionInfo.Algorithm.KeySchedule = StructTable->AlgSupported;
        break;
      }
      ExtAlgCount = StructTable->AlgCount & 0xF;
      StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
    }
  }

  SpdmResponse->MeasurementSpecificationSel = (UINT8)SpdmPrioritizeAlgorithm (
                                                mMeasurementSpecPriorityTable,
                                                ARRAY_SIZE(mMeasurementSpecPriorityTable),
                                                SpdmContext->LocalContext.Algorithm.MeasurementSpec,
                                                SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec
                                                );
  SpdmResponse->MeasurementHashAlgo = SpdmPrioritizeAlgorithm (
                                        mMeasurementHashPriorityTable,
                                        ARRAY_SIZE(mMeasurementHashPriorityTable),
                                        SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo,
                                        SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo
                                        );
  SpdmResponse->BaseAsymSel = SpdmPrioritizeAlgorithm (
                                mAsymPriorityTable,
                                ARRAY_SIZE(mAsymPriorityTable),
                                SpdmContext->LocalContext.Algorithm.BaseAsymAlgo,
                                SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo
                                );
  SpdmResponse->BaseHashSel = SpdmPrioritizeAlgorithm (
                                mHashPriorityTable,
                                ARRAY_SIZE(mHashPriorityTable),
                                SpdmContext->LocalContext.Algorithm.BaseHashAlgo,
                                SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo
                                );
  SpdmResponse->StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  SpdmResponse->StructTable[0].AlgCount = 0x20;
  SpdmResponse->StructTable[0].AlgSupported = (UINT16)SpdmPrioritizeAlgorithm (
                                                mDhePriorityTable,
                                                ARRAY_SIZE(mDhePriorityTable),
                                                SpdmContext->LocalContext.Algorithm.DHENamedGroup,
                                                SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup
                                                );
  SpdmResponse->StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  SpdmResponse->StructTable[1].AlgCount = 0x20;
  SpdmResponse->StructTable[1].AlgSupported = (UINT16)SpdmPrioritizeAlgorithm (
                                                mAeadPriorityTable,
                                                ARRAY_SIZE(mAeadPriorityTable),
                                                SpdmContext->LocalContext.Algorithm.AEADCipherSuite,
                                                SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite
                                                );
  SpdmResponse->StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
  SpdmResponse->StructTable[2].AlgCount = 0x20;
  SpdmResponse->StructTable[2].AlgSupported = (UINT16)SpdmPrioritizeAlgorithm (
                                                mReqAsymPriorityTable,
                                                ARRAY_SIZE(mReqAsymPriorityTable),
                                                SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg,
                                                SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg
                                                );
  SpdmResponse->StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  SpdmResponse->StructTable[3].AlgCount = 0x20;
  SpdmResponse->StructTable[3].AlgSupported = (UINT16)SpdmPrioritizeAlgorithm (
                                                mKeySchedulePriorityTable,
                                                ARRAY_SIZE(mKeySchedulePriorityTable),
                                                SpdmContext->LocalContext.Algorithm.KeySchedule,
                                                SpdmContext->ConnectionInfo.Algorithm.KeySchedule
                                                );
  //
  // Cache
  //
  Status = SpdmAppendMessageA (SpdmContext, SpdmResponse, *ResponseSize);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = SpdmResponse->MeasurementSpecificationSel;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmResponse->MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmResponse->BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmResponse->BaseHashSel;

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    if (SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    AlgoSize = GetSpdmMeasurementHashSize (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo);
    if (AlgoSize == 0) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }
  AlgoSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  if (AlgoSize == 0) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    AlgoSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
    if (AlgoSize == 0) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = SpdmResponse->StructTable[0].AlgSupported;
    SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = SpdmResponse->StructTable[1].AlgSupported;
    SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = SpdmResponse->StructTable[2].AlgSupported;
    SpdmContext->ConnectionInfo.Algorithm.KeySchedule = SpdmResponse->StructTable[3].AlgSupported;

    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
      AlgoSize = GetSpdmDhePubKeySize (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
      if (AlgoSize == 0) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
        SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
      AlgoSize = GetSpdmAeadKeySize (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite);
      if (AlgoSize == 0) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
      AlgoSize = GetSpdmReqAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
      if (AlgoSize == 0) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
    if (SpdmContext->ConnectionInfo.Algorithm.KeySchedule != SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
        return RETURN_SECURITY_VIOLATION;
      }
    }
  } else {
    SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = 0;
    SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = 0;
    SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = 0;
    SpdmContext->ConnectionInfo.Algorithm.KeySchedule = 0;
  }
  SpdmSetConnectionState (SpdmContext, SpdmConnectionStateNegotiated);

  return RETURN_SUCCESS;
}
