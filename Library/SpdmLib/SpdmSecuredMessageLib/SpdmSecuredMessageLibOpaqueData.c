/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/SpdmSecuredMessageLib.h>

#include <IndustryStandard/SpdmSecureMessage.h>
#include "SpdmCommonLibInternal.h"

UINTN
EFIAPI
SpdmGetOpaqueDataVersionSelectionDataSize (
  IN     VOID                 *SpdmContext
  )
{
  UINTN  Size;
  Size = sizeof(SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER) +
         sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER) +
         sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION);
  return (Size + 3) & ~3;
}

UINTN
EFIAPI
SpdmGetOpaqueDataSupportedVersionDataSize (
  IN     VOID                 *SpdmContext
  )
{
  UINTN  Size;
  Size = sizeof(SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER) +
         sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER) +
         sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION) +
         sizeof(SPDM_VERSION_NUMBER);
  return (Size + 3) & ~3;
}

RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  )
{
  UINTN                                             FinalDataSize;
  SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER   *GeneralOpaqueDataTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER        *OpaqueElementTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION   *OpaqueElementSupportVersion;
  SPDM_VERSION_NUMBER                               *VersionsList;

  FinalDataSize = SpdmGetOpaqueDataSupportedVersionDataSize(SpdmContext);
  if (*DataOutSize < FinalDataSize) {
    *DataOutSize = FinalDataSize;
    return RETURN_BUFFER_TOO_SMALL;
  }

  GeneralOpaqueDataTableHeader = DataOut;
  GeneralOpaqueDataTableHeader->SpecId = SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID;
  GeneralOpaqueDataTableHeader->OpaqueVersion = SECURE_MESSAGE_OPAQUE_VERSION;
  GeneralOpaqueDataTableHeader->TotalElements = 1;
  GeneralOpaqueDataTableHeader->Reserved = 0;

  OpaqueElementTableHeader = (VOID *)(GeneralOpaqueDataTableHeader + 1);
  OpaqueElementTableHeader->Id = SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF;
  OpaqueElementTableHeader->VendorLen = 0;
  OpaqueElementTableHeader->OpaqueElementDataLen = sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION) + sizeof(SPDM_VERSION_NUMBER);

  OpaqueElementSupportVersion = (VOID *)(OpaqueElementTableHeader + 1);
  OpaqueElementSupportVersion->SMDataVersion = SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
  OpaqueElementSupportVersion->SMDataID = SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
  OpaqueElementSupportVersion->VersionCount = 1;

  VersionsList = (VOID *)(OpaqueElementSupportVersion + 1);
  VersionsList->Alpha = 0;
  VersionsList->UpdateVersionNumber = 0;
  VersionsList->MinorVersion = 1;
  VersionsList->MajorVersion = 1;

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  )
{
  SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER   *GeneralOpaqueDataTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER        *OpaqueElementTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION   *OpaqueElementSupportVersion;
  SPDM_VERSION_NUMBER                               *VersionsList;

  if (DataInSize != SpdmGetOpaqueDataSupportedVersionDataSize(SpdmContext)) {
    return RETURN_UNSUPPORTED;
  }
  GeneralOpaqueDataTableHeader = DataIn;
  if ((GeneralOpaqueDataTableHeader->SpecId != SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
      (GeneralOpaqueDataTableHeader->OpaqueVersion != SECURE_MESSAGE_OPAQUE_VERSION) ||
      (GeneralOpaqueDataTableHeader->TotalElements != 1) ||
      (GeneralOpaqueDataTableHeader->Reserved != 0) ) {
    return RETURN_UNSUPPORTED;
  }
  OpaqueElementTableHeader = (VOID *)(GeneralOpaqueDataTableHeader + 1);
  if ((OpaqueElementTableHeader->Id != SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF) ||
      (OpaqueElementTableHeader->VendorLen != 0) ||
      (OpaqueElementTableHeader->OpaqueElementDataLen != sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION) + sizeof(SPDM_VERSION_NUMBER)) ) {
    return RETURN_UNSUPPORTED;
  }
  OpaqueElementSupportVersion = (VOID *)(OpaqueElementTableHeader + 1);
  if ((OpaqueElementSupportVersion->SMDataVersion != SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
      (OpaqueElementSupportVersion->SMDataID != SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION) ||
      (OpaqueElementSupportVersion->VersionCount != 1) ) {
    return RETURN_UNSUPPORTED;
  }
  VersionsList = (VOID *)(OpaqueElementSupportVersion + 1);
  if ((VersionsList->MinorVersion != 1) ||
      (VersionsList->MajorVersion != 1) ) {
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  )
{
  UINTN                                             FinalDataSize;
  SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER   *GeneralOpaqueDataTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER        *OpaqueElementTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION   *OpaqueElementVersionSection;

  FinalDataSize = SpdmGetOpaqueDataVersionSelectionDataSize(SpdmContext);
  if (*DataOutSize < FinalDataSize) {
    *DataOutSize = FinalDataSize;
    return RETURN_BUFFER_TOO_SMALL;
  }

  GeneralOpaqueDataTableHeader = DataOut;
  GeneralOpaqueDataTableHeader->SpecId = SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID;
  GeneralOpaqueDataTableHeader->OpaqueVersion = SECURE_MESSAGE_OPAQUE_VERSION;
  GeneralOpaqueDataTableHeader->TotalElements = 1;
  GeneralOpaqueDataTableHeader->Reserved = 0;

  OpaqueElementTableHeader = (VOID *)(GeneralOpaqueDataTableHeader + 1);
  OpaqueElementTableHeader->Id = SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF;
  OpaqueElementTableHeader->VendorLen = 0;
  OpaqueElementTableHeader->OpaqueElementDataLen = sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION);

  OpaqueElementVersionSection = (VOID *)(OpaqueElementTableHeader + 1);
  OpaqueElementVersionSection->SMDataVersion = SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
  OpaqueElementVersionSection->SMDataID = SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION;
  OpaqueElementVersionSection->SelectedVersion.Alpha = 0;
  OpaqueElementVersionSection->SelectedVersion.UpdateVersionNumber = 0;
  OpaqueElementVersionSection->SelectedVersion.MinorVersion = 1;
  OpaqueElementVersionSection->SelectedVersion.MajorVersion = 1;

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  )
{
  SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER   *GeneralOpaqueDataTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER        *OpaqueElementTableHeader;
  SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION   *OpaqueElementVersionSection;

  if (DataInSize != SpdmGetOpaqueDataVersionSelectionDataSize(SpdmContext)) {
    return RETURN_UNSUPPORTED;
  }
  GeneralOpaqueDataTableHeader = DataIn;
  if ((GeneralOpaqueDataTableHeader->SpecId != SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID) ||
      (GeneralOpaqueDataTableHeader->OpaqueVersion != SECURE_MESSAGE_OPAQUE_VERSION) ||
      (GeneralOpaqueDataTableHeader->TotalElements != 1) ||
      (GeneralOpaqueDataTableHeader->Reserved != 0) ) {
    return RETURN_UNSUPPORTED;
  }
  OpaqueElementTableHeader = (VOID *)(GeneralOpaqueDataTableHeader + 1);
  if ((OpaqueElementTableHeader->Id != SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF) ||
      (OpaqueElementTableHeader->VendorLen != 0) ||
      (OpaqueElementTableHeader->OpaqueElementDataLen != sizeof(SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION)) ) {
    return RETURN_UNSUPPORTED;
  }
  OpaqueElementVersionSection = (VOID *)(OpaqueElementTableHeader + 1);
  if ((OpaqueElementVersionSection->SMDataVersion != SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION) ||
      (OpaqueElementVersionSection->SMDataID != SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION) ||
      (OpaqueElementVersionSection->SelectedVersion.MinorVersion != 1) ||
      (OpaqueElementVersionSection->SelectedVersion.MajorVersion != 1) ) {
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}