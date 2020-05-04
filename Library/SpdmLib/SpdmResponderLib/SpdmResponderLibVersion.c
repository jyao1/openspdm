/** @file
  EDKII SpdmIo Stub

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
  MY_SPDM_VERSION_RESPONSE    *SpdmResponse;

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

  return RETURN_SUCCESS;
}

