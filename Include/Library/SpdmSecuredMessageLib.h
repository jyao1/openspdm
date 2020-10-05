/** @file
  SPDM Secured Message library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURED_MESSAGE_LIB_H__
#define __SPDM_SECURED_MESSAGE_LIB_H__

#include <Library/SpdmCommonLib.h>

RETURN_STATUS
EFIAPI
SpdmEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

RETURN_STATUS
EFIAPI
SpdmDecodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  );



UINTN
EFIAPI
SpdmGetOpaqueDataSupportedVersionDataSize (
  IN     VOID                 *SpdmContext
  );

RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

UINTN
EFIAPI
SpdmGetOpaqueDataVersionSelectionDataSize (
  IN     VOID                 *SpdmContext
  );

RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

#endif