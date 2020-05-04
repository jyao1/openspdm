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
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  StructTable[3];
} SPDM_ALGORITHMS_RESPONSE_MINE;
#pragma pack()

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
  SPDM_ALGORITHMS_RESPONSE_MINE                  *SpdmResponse;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;
  UINTN                                          Index;
  SPDM_DEVICE_CONTEXT                            *SpdmContext;

  SpdmContext = Context;

  ASSERT (*ResponseSize >= sizeof(SPDM_ALGORITHMS_RESPONSE_MINE));
  *ResponseSize = sizeof(SPDM_ALGORITHMS_RESPONSE_MINE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmResponse->Header.RequestResponseCode = SPDM_ALGORITHMS;
  SpdmResponse->Header.Param1 = 3; // Number of Algorithms Structure Tables
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->Length = (UINT16)*ResponseSize;
  SpdmResponse->MeasurementSpecificationSel = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;

  SpdmRequest = Request;
  StructTable = (VOID *)((UINTN)SpdmRequest +
                          sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                          sizeof(UINT32) * SpdmRequest->ExtAsymCount +
                          sizeof(UINT32) * SpdmRequest->ExtHashCount
                          );
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmRequest->BaseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmRequest->BaseHashAlgo;
  for (Index = 0; Index < SpdmRequest->Header.Param1; Index++) {
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

  SpdmResponse->MeasurementHashAlgo = SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo &
                                      SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo;
  SpdmResponse->BaseAsymSel = SpdmContext->LocalContext.Algorithm.BaseAsymAlgo &
                              SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo;
  SpdmResponse->BaseHashSel = SpdmContext->LocalContext.Algorithm.BaseHashAlgo &
                              SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo;
  SpdmResponse->StructTable[0].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE;
  SpdmResponse->StructTable[0].AlgCount = 0x20;
  SpdmResponse->StructTable[0].AlgSupported = SpdmContext->LocalContext.Algorithm.DHENamedGroup &
                                              SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup;
  SpdmResponse->StructTable[1].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD;
  SpdmResponse->StructTable[1].AlgCount = 0x20;
  SpdmResponse->StructTable[1].AlgSupported = SpdmContext->LocalContext.Algorithm.AEADCipherSuite &
                                              SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite;
  SpdmResponse->StructTable[2].AlgType = SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE;
  SpdmResponse->StructTable[2].AlgCount = 0x20;
  SpdmResponse->StructTable[2].AlgSupported = SpdmContext->LocalContext.Algorithm.KeySchedule &
                                              SpdmContext->ConnectionInfo.Algorithm.KeySchedule;

  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmResponse->MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmResponse->BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmResponse->BaseHashSel;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = SpdmResponse->StructTable[0].AlgSupported;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = SpdmResponse->StructTable[0].AlgSupported;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = SpdmResponse->StructTable[0].AlgSupported;

  return RETURN_SUCCESS;
}

