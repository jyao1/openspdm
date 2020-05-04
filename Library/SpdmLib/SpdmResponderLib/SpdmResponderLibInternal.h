/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_RESPONDER_LIB_INTERNAL_H__
#define __SPDM_RESPONDER_LIB_INTERNAL_H__

#include <Library/SpdmResponderLib.h>
#include "SpdmCommonLibInternal.h"

RETURN_STATUS
EFIAPI
SpdmGetResponseVersion (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseCapability (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseAlgorithm (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseDigest (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseCertificate (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseChallenge (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseMeasurement (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseKeyExchange (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseFinish (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponsePskExchange (
  IN     VOID                 *SpdmContext,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponsePskFinish (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseEndSession (
  IN     VOID                 *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
SpdmReceiveRequest (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  );

RETURN_STATUS
SpdmSendResponse (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response
  );

RETURN_STATUS
SpdmReceiveRequestSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT8                   SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  );

RETURN_STATUS
SpdmSendResponseSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT8                   SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response
  );

SPDM_SESSION_INFO *
SpdmAllocateSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
     OUT UINT8                     *SessionId
  );

#endif