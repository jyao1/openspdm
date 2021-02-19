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
  UINT8                         TH2HashData[64];
  UINT32                        AlgoSize;
  UINT16                        ResponderContextLength;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  // Check capabilities even if GET_CAPABILITIES is not sent.
  // Assuming capabilities are provisioned.
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  {
    // Double check if algorithm has been provisioned, because ALGORITHM might be skipped.
    if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
      if (SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
      AlgoSize = GetSpdmMeasurementHashSize (SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo);
      if (AlgoSize == 0) {
        SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
        return RETURN_SUCCESS;
      }
    }
    AlgoSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    if (AlgoSize == 0) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    if (SpdmContext->ConnectionInfo.Algorithm.KeySchedule != SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_PSK_EXCHANGE, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
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

  MeasurementSummaryHashSize = SpdmGetMeasurementSummaryHashSize (SpdmContext, FALSE, SpdmRequest->Header.Param1);
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
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
    ResponderContextLength = DEFAULT_CONTEXT_LENGTH;
  } else {
    ResponderContextLength = 0;
  }
  TotalSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE) +
              MeasurementSummaryHashSize +
              ResponderContextLength +
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
  if (RspSessionId == (INVALID_SESSION_ID & 0xFFFF)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, SessionId, TRUE);
  if (SessionInfo == NULL) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0, ResponseSize, Response);
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

  SpdmResponse->ResponderContextLength = ResponderContextLength;
  SpdmResponse->OpaqueLength = (UINT16)OpaquePskExchangeRspSize;

  Ptr = (VOID *)(SpdmResponse + 1);
  
  Result = SpdmGenerateMeasurementSummaryHash (SpdmContext, FALSE, SpdmRequest->Header.Param1, Ptr);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += MeasurementSummaryHashSize;
  
  if (ResponderContextLength != 0) {
    SpdmGetRandomNumber (ResponderContextLength, Ptr);
    Ptr += ResponderContextLength;
  }

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

  SpdmSetSessionState (SpdmContext, SessionId, SpdmSessionStateHandshaking);

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT)) {
    // No need to receive PSK_FINISH, enter application phase directly.

    DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", SessionId));
    Status = SpdmCalculateTH2Hash (SpdmContext, SessionInfo, FALSE, TH2HashData);
    if (RETURN_ERROR(Status)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    Status = SpdmGenerateSessionDataKey (SessionInfo->SecuredMessageContext, TH2HashData);
    if (RETURN_ERROR(Status)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }

    SpdmSetSessionState (SpdmContext, SessionId, SpdmSessionStateEstablished);
  }

  return RETURN_SUCCESS;
}

