/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM PSK_EXCHANGE request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetResponsePskExchange (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_PSK_EXCHANGE_REQUEST     *SpdmRequest;
  SPDM_PSK_EXCHANGE_RESPONSE    *SpdmResponse;
  BOOLEAN                       Result;
  UINT8                         SlotNum;
  UINT32                        SessionId;
  UINT32                        MeasurementSummaryHashSize;
  UINT32                        HmacSize;
  UINT8                         *Ptr;
  SPDM_SESSION_INFO             *SessionInfo;
  UINTN                         TotalSize;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  UINT16                        ReqSessionId;
  UINT16                        RspSessionId;
  RETURN_STATUS                 Status;
  UINTN                         OpaquePskExchangeRspSize;
  UINT8                         TH1HashData[64];

  SpdmContext = Context;
  SpdmRequest = Request;

  if ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_VERSION_RECEIVE_FLAG) == 0) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
    if (SpdmContext->EncapContext.ErrorState != SPDM_STATUS_SUCCESS) {
      DEBUG((DEBUG_INFO, "SpdmGetResponsePskExchange fail due to Mutual Auth fail\n"));
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  SlotNum = SpdmRequest->Header.Param2;
  if (SlotNum >= SpdmContext->LocalContext.SlotCount) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  MeasurementSummaryHashSize = SpdmGetMeasurementSummaryHashSize (SpdmContext, SpdmRequest->Header.Param1);
  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (RequestSize < sizeof(SPDM_PSK_EXCHANGE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (RequestSize < sizeof(SPDM_PSK_EXCHANGE_REQUEST) +
                    SpdmRequest->PSKHintLength +
                    SpdmRequest->RequesterContextLength +
                    SpdmRequest->OpaqueLength) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  RequestSize = sizeof(SPDM_PSK_EXCHANGE_REQUEST) +
                SpdmRequest->PSKHintLength +
                SpdmRequest->RequesterContextLength +
                SpdmRequest->OpaqueLength;

  Ptr = (UINT8 *)Request + sizeof(SPDM_PSK_EXCHANGE_REQUEST) + SpdmRequest->PSKHintLength + SpdmRequest->RequesterContextLength;
  Status = SpdmProcessOpaqueDataSupportedVersionData (SpdmContext, SpdmRequest->OpaqueLength, Ptr);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  OpaquePskExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);
  TotalSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              MeasurementSummaryHashSize +
              DEFAULT_CONTEXT_LENGTH +
              OpaquePskExchangeRspSize +
              HmacSize;

  ASSERT (*ResponseSize >= TotalSize);
  *ResponseSize = TotalSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_PSK_EXCHANGE_RSP;
  SpdmResponse->Header.Param1 = 0;

  ReqSessionId = SpdmRequest->ReqSessionID;
  RspSessionId = SpdmAllocateRspSessionId (SpdmContext);
  SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, SessionId, TRUE);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageK (SessionInfo, Request, RequestSize);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SpdmResponse->RspSessionID = RspSessionId;
  SpdmResponse->Reserved = 0;

  SpdmResponse->ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
  SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;

  Ptr = (VOID *)(SpdmResponse + 1);
  
  Result = SpdmGenerateMeasurementSummaryHash (SpdmContext, SpdmRequest->Header.Param1, Ptr);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += MeasurementSummaryHashSize;
  
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += DEFAULT_CONTEXT_LENGTH;

  Status = SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaquePskExchangeRspSize, Ptr);
  ASSERT_RETURN_ERROR(Status);
  Ptr += OpaquePskExchangeRspSize;

  Status = SpdmAppendMessageK (SessionInfo, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionHandshakeKey[%x]\n", SessionId));
  Status = SpdmCalculateTH1Hash (SpdmContext, SessionInfo, FALSE, TH1HashData);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Status = SpdmGenerateSessionHandshakeKey (SessionInfo->SecuredMessageContext, TH1HashData);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Result = SpdmGeneratePskExchangeRspHmac (SpdmContext, SessionInfo, Ptr);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE_RSP, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Status = SpdmAppendMessageK (SessionInfo, Ptr, HmacSize);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += HmacSize;

  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);
  SpdmContext->SpdmCmdReceiveState |= SPDM_PSK_EXCHANGE_RECEIVE_FLAG;

  return RETURN_SUCCESS;
}

