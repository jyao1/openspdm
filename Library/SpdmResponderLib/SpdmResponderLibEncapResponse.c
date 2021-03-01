/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Get the SPDM encapsulated request.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapRequestSize             Size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  EncapRequest                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_ENCAP_REQUEST) (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  );

/**
  Process the SPDM encapsulated response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapResponseSize            Size in bytes of the encapsulated response data.
  @param  EncapResponse                A pointer to the encapsulated response data.
  @param  Continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
typedef
RETURN_STATUS
(EFIAPI *SPDM_PROCESS_ENCAP_RESPONSE) (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  );

typedef struct {
  UINT8                           RequestOpCode;
  SPDM_GET_ENCAP_REQUEST          GetEncapRequest;
  SPDM_PROCESS_ENCAP_RESPONSE     ProcessEncapResponse;
} SPDM_ENCAP_RESPONSE_STRUCT;

SPDM_ENCAP_RESPONSE_STRUCT mEncapResponsestruct[] = {
  {SPDM_GET_DIGESTS,     SpdmGetEncapReqestGetDigest,      SpdmProcessEncapResponseDigest},
  {SPDM_GET_CERTIFICATE, SpdmGetEncapReqestGetCertificate, SpdmProcessEncapResponseCertificate},
  {SPDM_CHALLENGE,       SpdmGetEncapReqestChallenge,      SpdmProcessEncapResponseChallengeAuth},
  {SPDM_KEY_UPDATE,      SpdmGetEncapReqestKeyUpdate,      SpdmProcessEncapResponseKeyUpdate},
};

SPDM_ENCAP_RESPONSE_STRUCT *
SpdmGetEncapStructViaOpCode (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                RequestOpCode
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE(mEncapResponsestruct); Index++) {
    if (mEncapResponsestruct[Index].RequestOpCode == RequestOpCode) {
      return &mEncapResponsestruct[Index];
    }
  }
  ASSERT (FALSE);
  return NULL;
}

VOID
SpdmEncapMoveToNextOpCode (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  UINT8  Index;

  ASSERT (SpdmContext->EncapContext.RequestOpCodeCount <= MAX_ENCAP_REQUEST_OP_CODE_SEQUENCE_COUNT);
  if (SpdmContext->EncapContext.CurrentRequestOpCode == 0) {
    SpdmContext->EncapContext.CurrentRequestOpCode = SpdmContext->EncapContext.RequestOpCodeSequence[0];
    return ;
  }
  for (Index = 0; Index < SpdmContext->EncapContext.RequestOpCodeCount; Index ++) {
    if (SpdmContext->EncapContext.CurrentRequestOpCode == SpdmContext->EncapContext.RequestOpCodeSequence[Index]) {
      SpdmContext->EncapContext.CurrentRequestOpCode = SpdmContext->EncapContext.RequestOpCodeSequence[Index + 1];
      return ;
    }
  }
  ASSERT (FALSE);
}

/**
  Process a SPDM encapsulated response.

  @param  SpdmContext                  The SPDM context for the device.
  @param  EncapResponseSize            Size in bytes of the request data.
  @param  EncapResponse                A pointer to the request data.
  @param  EncapRequestSize             Size in bytes of the response data.
  @param  EncapRequest                 A pointer to the response data.

  @retval RETURN_SUCCESS               The SPDM encapsulated request is generated successfully.
  @retval RETURN_UNSUPPORTED           Do not know how to process the request.
**/
RETURN_STATUS
SpdmProcessEncapsulatedResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  RETURN_STATUS               Status;
  BOOLEAN                     Continue;
  SPDM_ENCAP_RESPONSE_STRUCT  *EncapResponseStruct;

  // Process previous response
  Continue = FALSE;

  if (SpdmContext->EncapContext.CurrentRequestOpCode != 0) {
    EncapResponseStruct = SpdmGetEncapStructViaOpCode (SpdmContext, SpdmContext->EncapContext.CurrentRequestOpCode);
    ASSERT (EncapResponseStruct != NULL);
    if (EncapResponseStruct == NULL) {
      return RETURN_UNSUPPORTED;
    }
    ASSERT (EncapResponseStruct->ProcessEncapResponse != NULL);
    if (EncapResponseStruct->ProcessEncapResponse == NULL) {
      return RETURN_UNSUPPORTED;
    }
    Status = EncapResponseStruct->ProcessEncapResponse (SpdmContext, EncapResponseSize, EncapResponse, &Continue);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }

  SpdmContext->EncapContext.RequestId += 1;

  // Move to next request
  if (!Continue) {
    SpdmEncapMoveToNextOpCode (SpdmContext);
  }

  if (SpdmContext->EncapContext.CurrentRequestOpCode == 0) {
    // No more work to do - stop
    *EncapRequestSize = 0;
    SpdmContext->EncapContext.CurrentRequestOpCode = 0;
    return RETURN_SUCCESS;
  }

  // Process the next request
  EncapResponseStruct = SpdmGetEncapStructViaOpCode (SpdmContext, SpdmContext->EncapContext.CurrentRequestOpCode);
  ASSERT (EncapResponseStruct != NULL);
  if (EncapResponseStruct == NULL) {
    return RETURN_UNSUPPORTED;
  }
  ASSERT (EncapResponseStruct->GetEncapRequest != NULL);
  if (EncapResponseStruct->GetEncapRequest == NULL) {
    return RETURN_UNSUPPORTED;
  }
  Status = EncapResponseStruct->GetEncapRequest (SpdmContext, EncapRequestSize, EncapRequest);
  return Status;
}

/**
  This function initializes the mut_auth encapsulated state.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MutAuthRequested             Indicate of the MutAuthRequested through KEY_EXCHANGE or CHALLENG response.
**/
VOID
SpdmInitMutAuthEncapState (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MutAuthRequested
  )
{
  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.CurrentRequestOpCode = 0x00;
  if (MutAuthRequested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS) {
    SpdmContext->EncapContext.CurrentRequestOpCode = SPDM_GET_DIGESTS;
  }
  SpdmContext->EncapContext.RequestId = 0;
  SpdmContext->EncapContext.LastEncapRequestSize = 0;
  ZeroMem (&SpdmContext->EncapContext.LastEncapRequestHeader, sizeof(SpdmContext->EncapContext.LastEncapRequestHeader));
  SpdmContext->EncapContext.CertificateChainBuffer.BufferSize = 0;
  SpdmContext->ResponseState = SpdmResponseStateProcessingEncap;

  //
  // Clear Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);
  
  //
  // Possible Sequence:
  // 2. Session Mutual Auth: (SpdmContext->LastSpdmRequestSessionIdValid)
  //    2.1 GET_DIGEST/GET_CERTIFICATE (SpdmContext->EncapContext.ReqSlotNum != 0xFF)
  //    2.2 GET_DIGEST (SpdmContext->EncapContext.ReqSlotNum == 0xFF)
  //    2.3 N/A (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
  //
  ZeroMem (SpdmContext->EncapContext.RequestOpCodeSequence, sizeof(SpdmContext->EncapContext.RequestOpCodeSequence));
  // Session Mutual Auth
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0) ||
      (MutAuthRequested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED)) {
    // no encap is required
    SpdmContext->EncapContext.RequestOpCodeCount = 0;
  } else if (SpdmContext->EncapContext.ReqSlotNum != 0xFF) {
    SpdmContext->EncapContext.RequestOpCodeCount = 2;
    SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_GET_DIGESTS;
    SpdmContext->EncapContext.RequestOpCodeSequence[1] = SPDM_GET_CERTIFICATE;
  } else {
    SpdmContext->EncapContext.RequestOpCodeCount = 1;
    SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_GET_DIGESTS;
  }
}

/**
  This function initializes the basic_mut_auth encapsulated state.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  BasicMutAuthRequested        Indicate of the MutAuthRequested through CHALLENG response.
**/
VOID
SpdmInitBasicMutAuthEncapState (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                BasicMutAuthRequested
  )
{
  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.CurrentRequestOpCode = 0x00;
  SpdmContext->EncapContext.RequestId = 0;
  SpdmContext->EncapContext.LastEncapRequestSize = 0;
  ZeroMem (&SpdmContext->EncapContext.LastEncapRequestHeader, sizeof(SpdmContext->EncapContext.LastEncapRequestHeader));
  SpdmContext->EncapContext.CertificateChainBuffer.BufferSize = 0;
  SpdmContext->ResponseState = SpdmResponseStateProcessingEncap;

  //
  // Clear Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);
  
  //
  // Possible Sequence:
  // 1. Basic Mutual Auth:
  //    1.1 GET_DIGEST/GET_CERTIFICATE/CHALLENGE (SpdmContext->EncapContext.ReqSlotNum != 0xFF)
  //    1.2 GET_DIGEST/CHALLENGE (SpdmContext->EncapContext.ReqSlotNum == 0xFF)
  //    1.3 CHALLENGE (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP)
  //
  ZeroMem (SpdmContext->EncapContext.RequestOpCodeSequence, sizeof(SpdmContext->EncapContext.RequestOpCodeSequence));
  // Basic Mutual Auth
  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, 0)) {
    SpdmContext->EncapContext.RequestOpCodeCount = 1;
    SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_CHALLENGE;
  } else if (SpdmContext->EncapContext.ReqSlotNum != 0xFF) {
    SpdmContext->EncapContext.RequestOpCodeCount = 3;
    SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_GET_DIGESTS;
    SpdmContext->EncapContext.RequestOpCodeSequence[1] = SPDM_GET_CERTIFICATE;
    SpdmContext->EncapContext.RequestOpCodeSequence[2] = SPDM_CHALLENGE;
  } else {
    SpdmContext->EncapContext.RequestOpCodeCount = 2;
    SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_GET_DIGESTS;
    SpdmContext->EncapContext.RequestOpCodeSequence[1] = SPDM_CHALLENGE;
  }
}

/**
  This function initializes the key_update encapsulated state.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmInitKeyUpdateEncapState (
  IN     VOID                 *Context
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  SpdmContext = Context;

  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.CurrentRequestOpCode = 0x00;
  SpdmContext->EncapContext.RequestId = 0;
  SpdmContext->EncapContext.LastEncapRequestSize = 0;
  ZeroMem (&SpdmContext->EncapContext.LastEncapRequestHeader, sizeof(SpdmContext->EncapContext.LastEncapRequestHeader));
  SpdmContext->EncapContext.CertificateChainBuffer.BufferSize = 0;
  SpdmContext->ResponseState = SpdmResponseStateProcessingEncap;

  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);

  ZeroMem (SpdmContext->EncapContext.RequestOpCodeSequence, sizeof(SpdmContext->EncapContext.RequestOpCodeSequence));
  SpdmContext->EncapContext.RequestOpCodeCount = 1;
  SpdmContext->EncapContext.RequestOpCodeSequence[0] = SPDM_KEY_UPDATE;
}

/**
  Process the SPDM ENCAPSULATED_REQUEST request and return the response.

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
SpdmGetResponseEncapsulatedRequest (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_ENCAPSULATED_REQUEST_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT                    *SpdmContext;
  VOID                                   *EncapRequest;
  UINTN                                  EncapRequestSize;
  RETURN_STATUS                          Status;
  SPDM_GET_ENCAPSULATED_REQUEST_REQUEST  *SpdmRequest;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_GET_ENCAPSULATED_REQUEST, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateProcessingEncap) {
    if (SpdmContext->ResponseState == SpdmResponseStateNormal) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }

  if (RequestSize != sizeof(SPDM_GET_ENCAPSULATED_REQUEST_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  ASSERT (*ResponseSize > sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE));
  ZeroMem (Response, *ResponseSize);

  SpdmResponse = Response;
  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_ENCAPSULATED_REQUEST;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  EncapRequestSize = *ResponseSize - sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE);
  EncapRequest = SpdmResponse + 1;

  Status = SpdmProcessEncapsulatedResponse (Context, 0, NULL, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0, ResponseSize, Response);
    SpdmContext->ResponseState = SpdmResponseStateNormal;
    return RETURN_SUCCESS;
  }
  *ResponseSize = sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = SpdmContext->EncapContext.RequestId;

  if (EncapRequestSize == 0) {
    SpdmContext->ResponseState = SpdmResponseStateNormal;
  }

  return RETURN_SUCCESS;
}

/**
  Process the SPDM ENCAPSULATED_RESPONSE_ACK request and return the response.

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
SpdmGetResponseEncapsulatedResponseAck (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST  *SpdmRequest;
  UINTN                                       SpdmRequestSize;
  SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT                         *SpdmContext;
  VOID                                        *EncapResponse;
  UINTN                                       EncapResponseSize;
  VOID                                        *EncapRequest;
  UINTN                                       EncapRequestSize;
  RETURN_STATUS                               Status;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, FALSE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SPDM_DELIVER_ENCAPSULATED_RESPONSE, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  if (SpdmContext->ResponseState != SpdmResponseStateProcessingEncap) {
    if (SpdmContext->ResponseState == SpdmResponseStateNormal) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }

  if (RequestSize <= sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SpdmRequestSize = RequestSize;

  if (SpdmRequest->Header.Param1 != SpdmContext->EncapContext.RequestId) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  EncapResponse = (SpdmRequest + 1);
  EncapResponseSize = SpdmRequestSize - sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST);

  ASSERT (*ResponseSize > sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE));
  ZeroMem (Response, *ResponseSize);

  SpdmResponse = Response;
  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_ENCAPSULATED_RESPONSE_ACK;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;

  EncapRequestSize = *ResponseSize - sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE);
  EncapRequest = SpdmResponse + 1;
  if (EncapResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  Status = SpdmProcessEncapsulatedResponse (Context, EncapResponseSize, EncapResponse, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_RESPONSE_CODE, 0, ResponseSize, Response);
    SpdmContext->ResponseState = SpdmResponseStateNormal;
    return RETURN_SUCCESS;
  }

  *ResponseSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = SpdmContext->EncapContext.RequestId;
  if (EncapRequestSize == 0) {
    SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
    if (SpdmContext->EncapContext.ReqSlotNum != 0) {
      SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER;
      *ResponseSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + 1;
      *(UINT8 *)(SpdmResponse + 1) = SpdmContext->EncapContext.ReqSlotNum;
    }
    SpdmContext->ResponseState = SpdmResponseStateNormal;
  }

  return RETURN_SUCCESS;
}

/**
  This function handles the encap error response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ManagedBuffer                The managed buffer to be shrinked.
  @param  ShrinkBufferSize             The size in bytes of the size of the buffer to be shrinked.
  @param  ErrorCode                    Indicate the error code.

  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmHandleEncapErrorResponseMain (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT VOID                 *MBuffer,
  IN     UINTN                ShrinkBufferSize,
  IN     UINT8                ErrorCode
  )
{
  //
  // According to "Timing Specification for SPDM messages", RESPONSE_NOT_READY is only for responder.
  // RESPONSE_NOT_READY should not be sent by requester. No need to check it.
  //

  //
  // No need to shrink MessageMutB and MessageMutC, because any error will terminate the ENCAP MUT AUTH.
  // The sequence is fixed in CHALLENG_AUTH or KEY_EXCHANGE_RSP, the responder cannot issue encap request again.
  // If the requester restarts the mutual auth via CHALLENG or KEY_EXCHANGE, the encap will also restart.
  // Do it here just to align with requester.
  //
  ShrinkManagedBuffer(MBuffer, ShrinkBufferSize);
  return RETURN_DEVICE_ERROR;
}
