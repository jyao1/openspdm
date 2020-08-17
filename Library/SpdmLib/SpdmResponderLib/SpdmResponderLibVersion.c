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
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
} MY_SPDM_VERSION_RESPONSE;
#pragma pack()

RETURN_STATUS
EFIAPI
SpdmGetResponseVersion (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_VERSION_REQUEST    *SpdmRequest;
  UINTN                       SpdmRequestSize;
  MY_SPDM_VERSION_RESPONSE    *SpdmResponse;
  SPDM_DEVICE_CONTEXT         *SpdmContext;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize != sizeof(SPDM_GET_VERSION_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmRequest, SpdmRequestSize);


  ASSERT (*ResponseSize >= sizeof(MY_SPDM_VERSION_RESPONSE));
  *ResponseSize = sizeof(MY_SPDM_VERSION_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmResponse->Header.RequestResponseCode = SPDM_VERSION;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->VersionNumberEntryCount = 2;
  SpdmResponse->VersionNumberEntry[0].MajorVersion = 1;
  SpdmResponse->VersionNumberEntry[0].MinorVersion = 0;
  SpdmResponse->VersionNumberEntry[1].MajorVersion = 1;
  SpdmResponse->VersionNumberEntry[1].MinorVersion = 1;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmResponse, *ResponseSize);

  SpdmContext->ConnectionInfo.Version[0] = SPDM_MESSAGE_VERSION_10;
  SpdmContext->ConnectionInfo.Version[1] = SPDM_MESSAGE_VERSION_11;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_VERSION_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

