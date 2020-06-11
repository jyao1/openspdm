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

RETURN_STATUS
EFIAPI
FindCommonVersion (
    IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
    IN     UINT8                VersionNumberEntryCount,
    IN     SPDM_VERSION_NUMBER  *VersionNumberEntries,
       OUT SPDM_VERSION_NUMBER  *CommonVersion
  )
{
  RETURN_STATUS Status = RETURN_NOT_FOUND;
  UINT8         MajorMax = 0;
  UINT8         MinorMax = 0;
  UINT8         Idx = 0;

  for(; Idx < VersionNumberEntryCount; Idx++){
    UINT8 Major = VersionNumberEntries[Idx].MajorVersion;
    UINT8 Minor = VersionNumberEntries[Idx].MinorVersion;
    UINT8 Idx2 = 0;
    for(; Idx2 < MAX_SPDM_SUPPORTED_VERSION_COUNT; Idx2++){
      if( Major == SpdmContext->SupportedSPDMVersions[Idx2].MajorVersion &&
          Minor == SpdmContext->SupportedSPDMVersions[Idx2].MinorVersion &&
          Major >= MajorMax && Minor >= MinorMax){
            MajorMax = Major;
            MinorMax = Minor;
            *CommonVersion = SpdmContext->SupportedSPDMVersions[Idx2];
            Status = RETURN_SUCCESS;
            break;
          }
    } 
  }

  return Status;
}

RETURN_STATUS
EFIAPI
SpdmGetVersion (
  IN OUT     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINT8                *VersionCount,
     OUT VOID                 *VersionNumberEntries
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_VERSION_REQUEST                  SpdmRequest;
  SPDM_VERSION_RESPONSE_MAX                 SpdmResponse;
  UINTN                                     SpdmResponseSize;
  SPDM_VERSION_NUMBER                       CommonVersion;
  
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_VERSION;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_VERSION_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_VERSION) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_VERSION_RESPONSE) + SpdmResponse.VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER)) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_VERSION_RESPONSE) + SpdmResponse.VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER);
  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, &SpdmResponse, SpdmResponseSize);

  if (VersionCount != NULL) {
    if (*VersionCount < SpdmResponse.VersionNumberEntryCount) {
      *VersionCount = SpdmResponse.VersionNumberEntryCount;
      return RETURN_BUFFER_TOO_SMALL;
    }
    *VersionCount = SpdmResponse.VersionNumberEntryCount;
    if (VersionNumberEntries != NULL) {
      CopyMem (
        VersionNumberEntries,
        SpdmResponse.VersionNumberEntry,
        SpdmResponse.VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER)
        );
    

      // Find a supported version in VersionNumberEntries. Return ERROR if one not found.
      // Pick highest MajorVersion followed by highest MinorVersion.
      // Use this version for future transactions.
      Status = FindCommonVersion(SpdmContext, SpdmResponse.VersionNumberEntryCount, VersionNumberEntries, &CommonVersion);
      if (RETURN_ERROR(Status)){
        printf("Didnt find common supported version...\n");
        return RETURN_DEVICE_ERROR;
      }
      SpdmContext->SPDMVersion = (CommonVersion.MajorVersion << 4) + CommonVersion.MinorVersion; 
    }
  }
  return RETURN_SUCCESS;
}
