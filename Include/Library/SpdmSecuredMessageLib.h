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
SpdmDecodeResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmEncodeRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
  );

RETURN_STATUS
EFIAPI
SpdmDecodeRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                MessageSize,
  IN     VOID                 *Message,
  IN OUT UINTN                *RequestSize,
     OUT VOID                 *Request
  );

RETURN_STATUS
EFIAPI
SpdmEncodeResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                ResponseSize,
  IN     VOID                 *Response,
  IN OUT UINTN                *MessageSize,
     OUT VOID                 *Message
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