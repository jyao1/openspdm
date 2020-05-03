/** @file
  EDKII SpdmIo Stub

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

BOOLEAN
SpdmVerifyFinishHmac (
  IN  SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN  UINT8                SessionId,
  IN  UINT8                SlotNum,
  OUT UINT8                *Hmac
  )
{
  UINT8                         HmacData[MAX_HASH_SIZE];
  UINT8                         *CertBuffer;
  UINTN                         CertBufferSize;
  HMAC_ALL                      HmacFunc;
  UINTN                         HashSize;
  LARGE_MANAGED_BUFFER          THCurr = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_SESSION_INFO             *SessionInfo;
  
  SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
  if (SessionInfo == NULL) {
    ASSERT (FALSE);
    return FALSE;
  }

  if ((SpdmContext->LocalContext.CertificateChain[SlotNum] == NULL) || (SpdmContext->LocalContext.CertificateChainSize[SlotNum] == 0)) {
    return FALSE;
  }
  
  HmacFunc = GetSpdmHmacFunc (SpdmContext);
  HashSize = GetSpdmHashSize (SpdmContext);

  CertBuffer = (UINT8 *)SpdmContext->LocalContext.CertificateChain[SlotNum] + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.CertificateChainSize[SlotNum] - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  DEBUG((DEBUG_INFO, "Calc MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Calc THMessageCt Data :\n"));
  InternalDumpHex (CertBuffer, CertBufferSize);

  DEBUG((DEBUG_INFO, "Calc MessageK Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));

  DEBUG((DEBUG_INFO, "Calc MessageF Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageF), GetManagedBufferSize(&SpdmContext->Transcript.MessageF));

  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&THCurr, CertBuffer, CertBufferSize);
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageK), GetManagedBufferSize(&SpdmContext->Transcript.MessageK));
  AppendManagedBuffer (&THCurr, GetManagedBuffer(&SpdmContext->Transcript.MessageF), GetManagedBufferSize(&SpdmContext->Transcript.MessageF));

  ASSERT(SessionInfo->HashSize != 0);
  HmacFunc (GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), SessionInfo->RequestHandshakeSecret, SessionInfo->HashSize, HmacData);
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
SpdmGetResponseFinish (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  BOOLEAN                  Result;
  UINT32                   HmacSize;
  UINT8                    SlotNum;
  SPDM_FINISH_RESPONSE     *SpdmResponse;

  ASSERT (*ResponseSize >= sizeof(SPDM_FINISH_RESPONSE));
  *ResponseSize = sizeof(SPDM_FINISH_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_FINISH_RSP;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  HmacSize = GetSpdmHashSize (SpdmContext);

  if (RequestSize != sizeof(SPDM_FINISH_REQUEST) + HmacSize) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SlotNum = 0;
  Result = SpdmVerifyFinishHmac (SpdmContext, SessionId, SlotNum, (UINT8 *)Request + sizeof(SPDM_FINISH_REQUEST));
  if (!Result) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  
  AppendManagedBuffer (&SpdmContext->Transcript.MessageF, SpdmResponse, *ResponseSize);
  SpdmGenerateSessionDataKey (SpdmContext, SessionId);

  return RETURN_SUCCESS;
}

