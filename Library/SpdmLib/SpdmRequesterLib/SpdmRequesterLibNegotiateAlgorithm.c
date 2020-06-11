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
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE Dhe;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE Aead;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE KeySchedule;
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
  UINT32               ExtAsymSel[8];
  UINT32               ExtHashSel[8];
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[4];
} SPDM_ALGORITHMS_RESPONSE_MAX;
#pragma pack()

/*
  The negotiated data can be get via GetData.
*/
RETURN_STATUS
EFIAPI
SpdmNegotiateAlgorithms (
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
  
  ZeroMem (&SpdmRequest, sizeof(SpdmRequest));
  SpdmRequest.Header.SPDMVersion = SpdmContext->SPDMVersion;
  SpdmRequest.Header.RequestResponseCode = SPDM_NEGOTIATE_ALGORITHMS;
  SpdmRequest.Header.Param1 = 3; // Number of Algorithms Structure Tables
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.Length = sizeof(SpdmRequest);
  SpdmRequest.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
  SpdmRequest.BaseAsymAlgo = SpdmContext->LocalContext.Algorithm.BaseAsymAlgo;
  SpdmRequest.BaseHashAlgo = SpdmContext->LocalContext.Algorithm.BaseHashAlgo;
  SpdmRequest.ExtAsymCount = 0;
  SpdmRequest.ExtHashCount = 0;
  SpdmRequest.Dhe.AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  SpdmRequest.Dhe.AlgCount = 0x20;
  SpdmRequest.Dhe.AlgSupported = SpdmContext->LocalContext.Algorithm.DHENamedGroup;
  SpdmRequest.Aead.AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  SpdmRequest.Aead.AlgCount = 0x20;
  SpdmRequest.Aead.AlgSupported = SpdmContext->LocalContext.Algorithm.AEADCipherSuite;
  SpdmRequest.KeySchedule.AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  SpdmRequest.KeySchedule.AlgCount = 0x20;
  SpdmRequest.KeySchedule.AlgSupported = SpdmContext->LocalContext.Algorithm.KeySchedule;
  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_ALGORITHMS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_ALGORITHMS) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_ALGORITHMS_RESPONSE) + 
                         sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                         sizeof(UINT32) * SpdmResponse.ExtHashSelCount +
                         sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) * SpdmResponse.Header.Param1) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_ALGORITHMS_RESPONSE) + 
                     sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                     sizeof(UINT32) * SpdmResponse.ExtHashSelCount +
                     sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) * SpdmResponse.Header.Param1;
  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmResponse, SpdmResponseSize);
  
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmResponse.MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmResponse.BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmResponse.BaseHashSel;
  StructTable = (VOID *)((UINTN)&SpdmResponse +
                          sizeof(SPDM_ALGORITHMS_RESPONSE) +
                          sizeof(UINT32) * SpdmResponse.ExtAsymSelCount +
                          sizeof(UINT32) * SpdmResponse.ExtHashSelCount
                          );
  for (Index = 0; Index < SpdmResponse.Header.Param1; Index++) {
    switch (StructTable[Index].AlgType) {
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
      SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = StructTable[Index].AlgSupported;
      break;
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
      SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = StructTable[Index].AlgSupported;
      break;
    case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
      SpdmContext->ConnectionInfo.Algorithm.KeySchedule = StructTable[Index].AlgSupported;
      break;
    }
  }

  AlgoSize = GetSpdmMeasurementHashSize (SpdmContext);
  if (AlgoSize == 0xFFFFFFFF) {
    return RETURN_SECURITY_VIOLATION;
  }
  AlgoSize = GetSpdmHashSize (SpdmContext);
  if (AlgoSize == 0xFFFFFFFF) {
    return RETURN_SECURITY_VIOLATION;
  }
  AlgoSize = GetSpdmAsymSize (SpdmContext);
  if (AlgoSize == 0xFFFFFFFF) {
    return RETURN_SECURITY_VIOLATION;
  }
  AlgoSize = GetSpdmDHEKeySize (SpdmContext);
  if (AlgoSize == 0xFFFFFFFF) {
    return RETURN_SECURITY_VIOLATION;
  }

  return RETURN_SUCCESS;
}
