/** @file
  SPDM transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TRANSPORT_LIB_H__
#define __SPDM_TRANSPORT_LIB_H__

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

#endif