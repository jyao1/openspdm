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
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
  SPDM_VERSION_NUMBER  VersionNumberEntry[MAX_SPDM_VERSION_COUNT];
} SPDM_VERSION_RESPONSE_MAX;
#pragma pack()

/**
  This function sends GET_VERSION and receives VERSION.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmGetVersion (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_VERSION_REQUEST                  SpdmRequest;
  SPDM_VERSION_RESPONSE_MAX                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINTN                                     Index;
  UINT8                                     Version;
  UINT8                                     CompatibleVersionCount;
  SPDM_VERSION_NUMBER                       CompatibleVersionNumberEntry[MAX_SPDM_VERSION_COUNT];

  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;

  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_VERSION;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
  Status = SpdmAppendMessageA (SpdmContext, &SpdmRequest, sizeof(SpdmRequest));
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
  if (SpdmResponse.Header.SPDMVersion != SPDM_MESSAGE_VERSION_10) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    ShrinkManagedBuffer(&SpdmContext->Transcript.MessageA, sizeof(SpdmRequest));
    Status = SpdmHandleSimpleErrorResponse(SpdmContext, SpdmResponse.Header.Param1);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_VERSION) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_VERSION_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.VersionNumberEntryCount > MAX_SPDM_VERSION_COUNT) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.VersionNumberEntryCount == 0) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_VERSION_RESPONSE) + SpdmResponse.VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER)) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_VERSION_RESPONSE) + SpdmResponse.VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER);
  //
  // Cache data
  //
  Status = SpdmAppendMessageA (SpdmContext, &SpdmResponse, SpdmResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }
  CompatibleVersionCount = 0;

  ZeroMem (&CompatibleVersionNumberEntry, sizeof(CompatibleVersionNumberEntry));
  for (Index = 0; Index < SpdmResponse.VersionNumberEntryCount; Index++) {
    Version = (UINT8)((SpdmResponse.VersionNumberEntry[Index].MajorVersion << 4) |
                                                         SpdmResponse.VersionNumberEntry[Index].MinorVersion);

    if (Version == SPDM_MESSAGE_VERSION_11 || Version == SPDM_MESSAGE_VERSION_10) {
      CompatibleVersionNumberEntry[CompatibleVersionCount] = SpdmResponse.VersionNumberEntry[Index];
      CompatibleVersionCount++;
    }
  }
  if(CompatibleVersionCount == 0) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = CompatibleVersionCount;
  CopyMem (SpdmContext->ConnectionInfo.Version.SpdmVersion, CompatibleVersionNumberEntry, sizeof(SPDM_VERSION_NUMBER) * CompatibleVersionCount);

  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterVersion;
  return RETURN_SUCCESS;
}

/**
  This function sends GET_VERSION and receives VERSION.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  VersionCount                 VersionCount from the VERSION response.
  @param  VersionNumberEntries         VersionNumberEntries from the VERSION response.

  @retval RETURN_SUCCESS               The GET_VERSION is sent and the VERSION is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmGetVersion (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  UINTN         Retry;
  RETURN_STATUS Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmGetVersion(SpdmContext);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

