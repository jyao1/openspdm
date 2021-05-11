/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               Length;
  UINT8                MeasurementSpecification;
  UINT8                Reserved;
  UINT32               BaseAsymAlgo;
  UINT32               BaseHashAlgo;
  UINT8                Reserved2[12];
  UINT8                ExtAsymCount;
  UINT8                ExtHashCount;
  UINT16               Reserved3;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE StructTable[4];
} SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MINE;

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
  UINT32               ExtAsymSel;//ExtAsymSel and ExtHashSel are unique
  UINT32               ExtHashSel;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_ALGORITHMS_RESPONSE_MAX;
#pragma pack()

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmNegotiateAlgorithms (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  RETURN_STATUS                                  Status;
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST_MINE         SpdmRequest;
  SPDM_ALGORITHMS_RESPONSE_MAX                   SpdmResponse;
  UINTN                                          SpdmResponseSize;
  UINT32                                         AlgoSize;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;
  UINT8                                          FixedAlgSize;
  UINT8                                          ExtAlgCount;

  if (SpdmContext->ConnectionInfo.ConnectionState != SpdmConnectionStateAfterCapabilities) {
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&SpdmRequest, sizeof(SpdmRequest));
  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmRequest.Length = sizeof(SpdmRequest);
    SpdmRequest.Header.Param1 = 4; // Number of Algorithms Structure Tables
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmRequest.Length = sizeof(SpdmRequest) - sizeof(SpdmRequest.StructTable);
    SpdmRequest.Header.Param1 = 0;
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_NEGOTIATE_ALGORITHMS;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.MeasurementSpecification = SpdmContext->LocalContext.Algorithm.MeasurementSpec;
  SpdmRequest.BaseAsymAlgo = SpdmContext->LocalContext.Algorithm.BaseAsymAlgo;
  SpdmRequest.BaseHashAlgo = SpdmContext->LocalContext.Algorithm.BaseHashAlgo;
  SpdmRequest.ExtAsymCount = 0;
  SpdmRequest.ExtHashCount = 0;
  SpdmRequest.StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  SpdmRequest.StructTable[0].AlgCount = 0x20;
  SpdmRequest.StructTable[0].AlgSupported = SpdmContext->LocalContext.Algorithm.DHENamedGroup;
  SpdmRequest.StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  SpdmRequest.StructTable[1].AlgCount = 0x20;
  SpdmRequest.StructTable[1].AlgSupported = SpdmContext->LocalContext.Algorithm.AEADCipherSuite;
  SpdmRequest.StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG;
  SpdmRequest.StructTable[2].AlgCount = 0x20;
  SpdmRequest.StructTable[2].AlgSupported = SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg;
  SpdmRequest.StructTable[3].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  SpdmRequest.StructTable[3].AlgCount = 0x20;
  SpdmRequest.StructTable[3].AlgSupported = SpdmContext->LocalContext.Algorithm.KeySchedule;
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequest.Length, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  Status = SpdmAppendMessageA (SpdmContext, &SpdmRequest, SpdmRequest.Length);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    ShrinkManagedBuffer(&SpdmContext->Transcript.MessageA, SpdmRequest.Length);
    Status = SpdmHandleSimpleErrorResponse(SpdmContext, SpdmResponse.Header.Param1);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_ALGORITHMS) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_ALGORITHMS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.SPDMVersion != SpdmRequest.Header.SPDMVersion){
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.ExtAsymSelCount > 1) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.ExtHashSelCount > 1) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_ALGORITHMS_RESPONSE) +
                         sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                         sizeof(UINT32) * SpdmResponse.ExtHashSelCount +
                         sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) * SpdmResponse.Header.Param1) {
    return RETURN_DEVICE_ERROR;
  }
  StructTable = (VOID *)((UINTN)&SpdmResponse +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                            sizeof(UINT32) * SpdmResponse.ExtHashSelCount
                            );
  if (SpdmResponse.Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    for (Index = 0; Index < SpdmResponse.Header.Param1; Index++) {
      if ((UINTN)&SpdmResponse + SpdmResponseSize < (UINTN)StructTable) {
        return RETURN_DEVICE_ERROR;
      }
      if ((UINTN)&SpdmResponse + SpdmResponseSize - (UINTN)StructTable < sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE)) {
        return RETURN_DEVICE_ERROR;
      }
      FixedAlgSize = (StructTable->AlgCount >> 4) & 0xF;
      ExtAlgCount = StructTable->AlgCount & 0xF;
      if (FixedAlgSize != 2) {
        return RETURN_DEVICE_ERROR;
      }
      if (ExtAlgCount > 1) {
        return RETURN_DEVICE_ERROR;
      }
      if ((UINTN)&SpdmResponse + SpdmResponseSize - (UINTN)StructTable - sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) < sizeof(UINT32) * ExtAlgCount) {
        return RETURN_DEVICE_ERROR;
      }
      StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
    }
  }
  SpdmResponseSize = (UINTN)StructTable - (UINTN)&SpdmResponse;
  if (SpdmResponseSize != SpdmResponse.Length) {
    return RETURN_DEVICE_ERROR;
  }
  //
  // Cache data
  //
  Status = SpdmAppendMessageA (SpdmContext, &SpdmResponse, SpdmResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = SpdmResponse.MeasurementSpecificationSel;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmResponse.MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmResponse.BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmResponse.BaseHashSel;

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    if (SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
      return RETURN_SECURITY_VIOLATION;
    }
    AlgoSize = GetSpdmMeasurementHashSize (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo);
    if (AlgoSize == 0) {
      return RETURN_SECURITY_VIOLATION;
    }
  }
  AlgoSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  if (AlgoSize == 0) {
    return RETURN_SECURITY_VIOLATION;
  }
  if ((SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo&SpdmContext->LocalContext.Algorithm.BaseHashAlgo)==0){
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP)) {
    AlgoSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
    if (AlgoSize == 0) {
      return RETURN_SECURITY_VIOLATION;
    }
    if ((SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo&SpdmContext->LocalContext.Algorithm.BaseAsymAlgo)==0){
      return RETURN_DEVICE_ERROR;
    }
  }
  if (SpdmResponse.Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    StructTable = (VOID *)((UINTN)&SpdmResponse +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                            sizeof(UINT32) * SpdmResponse.ExtHashSelCount
                            );
    for (Index = 0; Index < SpdmResponse.Header.Param1; Index++) {
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
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
      AlgoSize = GetSpdmDhePubKeySize (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
      if (AlgoSize == 0) {
        return RETURN_SECURITY_VIOLATION;
      }
      if ((SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup&SpdmContext->LocalContext.Algorithm.DHENamedGroup)==0){
        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP) ||
        SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP)) {
      AlgoSize = GetSpdmAeadKeySize (SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite);
      if (AlgoSize == 0) {
        return RETURN_SECURITY_VIOLATION;
      }
      if ((SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite&SpdmContext->LocalContext.Algorithm.AEADCipherSuite)==0){
        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
      AlgoSize = GetSpdmReqAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
      if (AlgoSize == 0) {
        return RETURN_SECURITY_VIOLATION;
      }
      if ((SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg&SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg)==0){
        return RETURN_SECURITY_VIOLATION;
      }
    }
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP) ||
        SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
      if (SpdmContext->ConnectionInfo.Algorithm.KeySchedule != SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
        return RETURN_SECURITY_VIOLATION;
      }
      if ((SpdmContext->ConnectionInfo.Algorithm.KeySchedule&SpdmContext->LocalContext.Algorithm.KeySchedule)==0){
        return RETURN_SECURITY_VIOLATION;
      }
    }
  } else {
    SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = 0;
    SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = 0;
    SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = 0;
    SpdmContext->ConnectionInfo.Algorithm.KeySchedule = 0;
  }
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  return RETURN_SUCCESS;
}

/**
  This function sends NEGOTIATE_ALGORITHMS and receives ALGORITHMS.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The NEGOTIATE_ALGORITHMS is sent and the ALGORITHMS is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmNegotiateAlgorithms (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  UINTN         Retry;
  RETURN_STATUS Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmNegotiateAlgorithms(SpdmContext);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}
