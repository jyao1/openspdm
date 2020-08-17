/** @file
  SPDM common library.
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
SpdmResponderHandleResponseState (
  IN     VOID                 *Context,
  IN     UINT8                 RequestCode,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseRespondIfReady (
  IN     VOID                 *Context,
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
  IN     UINT32               SessionId,
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
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseEndSession (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseHeartbeat (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseKeyUpdate (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedRequest (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedResponseAck (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmGetEncapReqestGetDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  );

RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseDigest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
  OUT    BOOLEAN              *Continue
  );

RETURN_STATUS
EFIAPI
SpdmGetEncapReqestGetCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  );

RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
  OUT    BOOLEAN              *Continue
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

SPDM_GET_RESPONSE_FUNC
SpdmGetResponseFuncViaRequestCode (
  IN     UINT8                    RequestCode
  );

RETURN_STATUS
SpdmReceiveRequestSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request
  );

RETURN_STATUS
SpdmSendResponseSession (
  IN     SPDM_DEVICE_CONTEXT     *SpdmContext,
  IN     UINT32                  SessionId,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response
  );

UINT16
SpdmAllocateRspSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  );

#endif