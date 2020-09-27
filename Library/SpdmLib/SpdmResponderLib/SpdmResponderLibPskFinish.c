/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmResponderVerifyPskFinishHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  SPDM_SESSION_INFO         *SessionInfo,
  OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr;

  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext);

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));

  DEBUG((DEBUG_INFO, "Calc MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageK), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageK));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SessionInfo->SessionTranscript.MessageF), GetManagedBufferSize(&SessionInfo->SessionTranscript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  HmacFunc (SpdmContext, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->HandshakeSecret.RequestFinishedKey, SessionInfo->HashSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem(Hmac, HmacData, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyPskFinishHmac - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyPskFinishHmac - PASS !!!\n"));
  return TRUE;
}

RETURN_STATUS
EFIAPI
SpdmGetResponsePskFinish (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  BOOLEAN                      Result;
  UINT32                       HmacSize;
  SPDM_PSK_FINISH_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT          *SpdmContext;
  SPDM_SESSION_INFO            *SessionInfo;

  SpdmContext = Context;

  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  
  // remove HMAC
  HmacSize = GetSpdmHashSize (SpdmContext);

  if (RequestSize != sizeof(SPDM_PSK_FINISH_REQUEST) + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, Request, RequestSize - HmacSize);

  ASSERT (*ResponseSize >= sizeof(SPDM_PSK_FINISH_RESPONSE));
  *ResponseSize = sizeof(SPDM_PSK_FINISH_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_PSK_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  // Need regenerate the finishedkey
  SpdmGenerateSessionHandshakeKey (SpdmContext, SessionId, FALSE);
  Result = SpdmResponderVerifyPskFinishHmac (SpdmContext, SessionInfo, (UINT8 *)Request + sizeof(SPDM_PSK_FINISH_REQUEST));
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  
  AppendManagedBuffer (&SessionInfo->SessionTranscript.MessageF, SpdmResponse, *ResponseSize);
  SpdmGenerateSessionDataKey (SpdmContext, SessionId, FALSE);

  return RETURN_SUCCESS;
}

