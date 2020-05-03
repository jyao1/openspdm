/** @file
  EDKII SpdmIo Stub

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmVerifyPskFinishHmac (
  IN  SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN  UINT8                     SessionId,
  OUT UINT8                     *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  HMAC_ALL                      HmacFunc;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_SESSION_INFO             *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return FALSE;
  }

  HmacFunc = GetSpdmHmacFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc MessagePK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));

  DEBUG((DEBUG_INFO, "Calc MessagePF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessagePF), GetManagedBufferSize(&SpdmContext->Transcript.MessagePF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessagePK), GetManagedBufferSize(&SpdmContext->Transcript.MessagePK));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessagePF), GetManagedBufferSize(&SpdmContext->Transcript.MessagePF));

  ASSERT(SessionInfo->HashSize != 0);
  HmacFunc (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->RequestFinishedKey, SessionInfo->HashSize, HmacData);
  DEBUG((DEBUG_INFO, "Calc THCurr Hmac - "));
  InternalDumpData (HmacData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (CompareMem(Hmac, HmacData, HashSize) != 0) {
    return FALSE;
  }
  return TRUE;
}

RETURN_STATUS
EFIAPI
SpdmGetResponsePskFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  BOOLEAN                      Result;
  UINT32                       HmacSize;
  SPDM_PSK_FINISH_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_PSK_FINISH_RESPONSE));
  *ResponseSize = sizeof(SPDM_PSK_FINISH_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_PSK_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  HmacSize = GetSpdmHashSize (SpdmContext);

  if (RequestSize != sizeof(SPDM_PSK_FINISH_REQUEST) + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  // Need regenerate the finishedkey
  SpdmGenerateSessionHandshakeKey (SpdmContext, SessionId);
  Result = SpdmVerifyPskFinishHmac (SpdmContext, SessionId, (UINT8 *)Request + sizeof(SPDM_PSK_FINISH_REQUEST));
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  
  AppendManagedBuffer (&SpdmContext->Transcript.MessagePF, SpdmResponse, *ResponseSize);
  SpdmGenerateSessionDataKey (SpdmContext, SessionId);

  return RETURN_SUCCESS;
}

