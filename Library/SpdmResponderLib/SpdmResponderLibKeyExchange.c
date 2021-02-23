/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Process the SPDM KEY_EXCHANGE request and return the response.

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
SpdmGetResponseKeyExchange (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_KEY_EXCHANGE_REQUEST     *SpdmRequest;
  SPDM_KEY_EXCHANGE_RESPONSE    *SpdmResponse;
  UINTN                         DheKeySize;
  UINT32                        MeasurementSummaryHashSize;
  UINT32                        SignatureSize;
  UINT32                        HmacSize;
  UINT8                         *Ptr;
  UINT16                        OpaqueDataLength;
  BOOLEAN                       Result;
  UINT8                         SlotNum;
  UINT32                        SessionId;
  VOID                          *DHEContext;
  SPDM_SESSION_INFO             *SessionInfo;
  UINTN                         TotalSize;
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  UINT16                        ReqSessionId;
  UINT16                        RspSessionId;
  RETURN_STATUS                 Status;
  UINTN                         OpaqueKeyExchangeRspSize;
  UINT8                         TH1HashData[64];

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_EXCHANGE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP)) {
    if (SpdmContext->EncapContext.ErrorState != SPDM_STATUS_SUCCESS) {
      DEBUG((DEBUG_INFO, "SpdmGetResponseKeyExchange fail due to Mutual Auth fail\n"));
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  SlotNum = SpdmRequest->Header.Param2;
  if ((SlotNum != 0xFF) && (SlotNum >= SpdmContext->LocalContext.SlotCount)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SlotNum == 0xFF) {
    SlotNum = SpdmContext->LocalContext.ProvisionedSlotNum;
  }

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  HmacSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  DheKeySize = GetSpdmDhePubKeySize (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
  MeasurementSummaryHashSize = SpdmGetMeasurementSummaryHashSize (SpdmContext, FALSE, SpdmRequest->Header.Param1);

  if (RequestSize < sizeof(SPDM_KEY_EXCHANGE_REQUEST) +
                    DheKeySize +
                    sizeof(UINT16)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  OpaqueDataLength = *(UINT16 *)((UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DheKeySize);
  if (RequestSize < sizeof(SPDM_KEY_EXCHANGE_REQUEST) +
                    DheKeySize +
                    sizeof(UINT16) +
                    OpaqueDataLength) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  RequestSize = sizeof(SPDM_KEY_EXCHANGE_REQUEST) +
                DheKeySize +
                sizeof(UINT16) +
                OpaqueDataLength;

  Ptr = (UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DheKeySize + sizeof(UINT16);
  Status = SpdmProcessOpaqueDataSupportedVersionData (SpdmContext, OpaqueDataLength, Ptr);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  OpaqueKeyExchangeRspSize = SpdmGetOpaqueDataVersionSelectionDataSize (SpdmContext);

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    HmacSize = 0;
  }

  TotalSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE) +
              DheKeySize +
              MeasurementSummaryHashSize +
              sizeof(UINT16) +
              OpaqueKeyExchangeRspSize +
              SignatureSize +
              HmacSize;

  ASSERT (*ResponseSize >= TotalSize);
  *ResponseSize = TotalSize;
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_KEY_EXCHANGE_RSP;
  SpdmResponse->Header.Param1 = 0;

  ReqSessionId = SpdmRequest->ReqSessionID;
  RspSessionId = SpdmAllocateRspSessionId (SpdmContext);
  if (RspSessionId == (INVALID_SESSION_ID & 0xFFFF)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SessionId = (ReqSessionId << 16) | RspSessionId;
  SessionInfo = SpdmAssignSessionId (SpdmContext, SessionId, FALSE);
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

  SpdmResponse->MutAuthRequested = 0;
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP) &&
      (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, 0) ||
       SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0))) {
    SpdmResponse->MutAuthRequested = SpdmContext->LocalContext.MutAuthRequested;
  }
  if (SpdmResponse->MutAuthRequested != 0) {
    SpdmInitMutAuthEncapState (Context, SpdmResponse->MutAuthRequested);
    SpdmResponse->ReqSlotIDParam = (SpdmContext->EncapContext.ReqSlotNum & 0xF);
  } else {
    SpdmResponse->ReqSlotIDParam = 0;
  }

  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, SpdmResponse->RandomData);

  Ptr = (VOID *)(SpdmResponse + 1);
  DHEContext = SpdmSecuredMessageDheNew (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup);
  SpdmSecuredMessageDheGenerateKey (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext, Ptr, &DheKeySize);
  DEBUG((DEBUG_INFO, "Calc SelfKey (0x%x):\n", DheKeySize));
  InternalDumpHex (Ptr, DheKeySize);

  DEBUG((DEBUG_INFO, "Calc PeerKey (0x%x):\n", DheKeySize));
  InternalDumpHex ((UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize);

  Result = SpdmSecuredMessageDheComputeKey (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext, (UINT8 *)Request + sizeof(SPDM_KEY_EXCHANGE_REQUEST), DheKeySize, SessionInfo->SecuredMessageContext);
  SpdmSecuredMessageDheFree (SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup, DHEContext);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Ptr += DheKeySize;

  Result = SpdmGenerateMeasurementSummaryHash (SpdmContext, FALSE, SpdmRequest->Header.Param1, Ptr);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Ptr += MeasurementSummaryHashSize;

  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeRspSize;
  Ptr += sizeof(UINT16);
  Status = SpdmBuildOpaqueDataVersionSelectionData (SpdmContext, &OpaqueKeyExchangeRspSize, Ptr);
  ASSERT_RETURN_ERROR(Status);
  Ptr += OpaqueKeyExchangeRspSize;

  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = SpdmContext->LocalContext.LocalCertChainProvision[SlotNum];
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum];

  Status = SpdmAppendMessageK (SessionInfo, SpdmResponse, (UINTN)Ptr - (UINTN)SpdmResponse);
  if (RETURN_ERROR(Status)) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  Result = SpdmGenerateKeyExchangeRspSignature (SpdmContext, SessionInfo, Ptr);
  if (!Result) {
    SpdmFreeSessionId (SpdmContext, SessionId);
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_EXCHANGE_RSP, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmAppendMessageK (SessionInfo, Ptr, SignatureSize);
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

  Ptr += SignatureSize;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP)) {
    Result = SpdmGenerateKeyExchangeRspHmac (SpdmContext, SessionInfo, Ptr);
    if (!Result) {
      SpdmFreeSessionId (SpdmContext, SessionId);
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_KEY_EXCHANGE_RSP, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    Status = SpdmAppendMessageK (SessionInfo, Ptr, HmacSize);
    if (RETURN_ERROR(Status)) {
      SpdmFreeSessionId (SpdmContext, SessionId);
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }

    Ptr += HmacSize;
  }

  SessionInfo->MutAuthRequested = SpdmResponse->MutAuthRequested;
  SpdmSetSessionState (SpdmContext, SessionId, SpdmSessionStateHandshaking);

  return RETURN_SUCCESS;
}

