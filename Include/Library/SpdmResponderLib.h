/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_RESPONDER_LIB_H__
#define __SPDM_RESPONDER_LIB_H__

#include <Library/SpdmCommonLib.h>

typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_RESPONSE_FUNC) (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_RESPONSE_SESSION_FUNC) (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmRegisterGetResponseFunc (
  IN  VOID                    *SpdmContext,
  IN  SPDM_GET_RESPONSE_FUNC  GetResponseFunc
  );

RETURN_STATUS
EFIAPI
SpdmRegisterGetResponseSessionFunc (
  IN  VOID                            *SpdmContext,
  IN  SPDM_GET_RESPONSE_SESSION_FUNC  GetResponseFunc
  );

RETURN_STATUS
EFIAPI
SpdmReceiveSendData (
  IN     VOID                 *SpdmContext,
  IN     VOID                 *RequestBuffer,
  IN     UINTN                RequestBufferSize,
     OUT VOID                 *ResponseBuffer,
  IN OUT UINTN                *ResponseBufferSize
  );

RETURN_STATUS
EFIAPI
SpdmReceiveSendSessionData (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SessionId,
  IN     VOID                 *RequestBuffer,
  IN     UINTN                RequestBufferSize,
     OUT VOID                 *ResponseBuffer,
  IN OUT UINTN                *ResponseBufferSize
  );

RETURN_STATUS
EFIAPI
SpdmGenerateErrorResponse (
  IN     VOID                 *SpdmContext,
  IN     UINT8                ErrorCode,
  IN     UINT8                ErrorData,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

#endif