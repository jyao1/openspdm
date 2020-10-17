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

typedef enum {
  SpdmEncapResponseStateNotStarted,
  SpdmEncapResponseStateWaitForDigest,
  SpdmEncapResponseStateWaitForCertificate,
  SpdmEncapResponseStateWaitForChallengeAuth,
  SpdmEncapResponseStateMax,
} SPDM_ENCAP_RESPONSE_STATE;

typedef struct {
  SPDM_ENCAP_RESPONSE_STATE       EncapState;
  SPDM_PROCESS_ENCAP_RESPONSE     ProcessEncapResponse;
  SPDM_GET_ENCAP_REQUEST          ContinueGetEncapRequest;
  SPDM_GET_ENCAP_REQUEST          NextGetEncapRequest;
} SPDM_ENCAP_RESPONSE_STRUCT;

//
// Basic Mutual Auth
//
SPDM_ENCAP_RESPONSE_STRUCT  mSpdmEncapStruct[] = {
  {SpdmEncapResponseStateNotStarted,           NULL,                                  NULL,                             SpdmGetEncapReqestGetDigest     },
  {SpdmEncapResponseStateWaitForDigest,        SpdmProcessEncapResponseDigest,        NULL,                             SpdmGetEncapReqestGetCertificate},
  {SpdmEncapResponseStateWaitForCertificate,   SpdmProcessEncapResponseCertificate,   SpdmGetEncapReqestGetCertificate, SpdmGetEncapReqestChallenge     },
  {SpdmEncapResponseStateWaitForChallengeAuth, SpdmProcessEncapResponseChallengeAuth, NULL,                             NULL                            },
  {SpdmEncapResponseStateMax,                  NULL,                                  NULL,                             NULL                            },
};

//
// Session Mutual Auth
//
SPDM_ENCAP_RESPONSE_STRUCT  mSpdmEncapSessionStruct[] = {
  {SpdmEncapResponseStateNotStarted,           NULL,                                  NULL,                             SpdmGetEncapReqestGetDigest     },
  {SpdmEncapResponseStateWaitForDigest,        SpdmProcessEncapResponseDigest,        NULL,                             SpdmGetEncapReqestGetCertificate},
  {SpdmEncapResponseStateWaitForCertificate,   SpdmProcessEncapResponseCertificate,   SpdmGetEncapReqestGetCertificate, NULL                            },
  {SpdmEncapResponseStateMax,                  NULL,                                  NULL,                             NULL                            },
};

/**
  This function gets the encap structure via state.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapState                   Encap state.

  @return SPDM encap response structure
**/
SPDM_ENCAP_RESPONSE_STRUCT *
SpdmGetEncapStructViaState (
  IN     SPDM_DEVICE_CONTEXT             *SpdmContext,
  IN     SPDM_ENCAP_RESPONSE_STATE       EncapState
  )
{
  UINTN                Index;

  if (SpdmContext->LastSpdmRequestSessionIdValid) {
    for (Index = 0; Index < sizeof(mSpdmEncapSessionStruct)/sizeof(mSpdmEncapSessionStruct[0]); Index++) {
      if (EncapState == mSpdmEncapSessionStruct[Index].EncapState) {
        return &mSpdmEncapSessionStruct[Index];
      }
    }
  } else {
    for (Index = 0; Index < sizeof(mSpdmEncapStruct)/sizeof(mSpdmEncapStruct[0]); Index++) {
      if (EncapState == mSpdmEncapStruct[Index].EncapState) {
        return &mSpdmEncapStruct[Index];
      }
    }
  }
  return NULL;
}

/**
  Process a SPDM encapsulated response.

  @param  SpdmContext                  The SPDM context for the device.
  @param  RequestId                    Indicate if the request ID for the encapsulated message.
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
  IN OUT UINT8                *RequestId,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  RETURN_STATUS               Status;
  BOOLEAN                     Continue;
  SPDM_ENCAP_RESPONSE_STRUCT  *EncapResponseStruct;

  EncapResponseStruct = SpdmGetEncapStructViaState (SpdmContext, SpdmContext->EncapContext.EncapState);
  ASSERT (EncapResponseStruct != NULL);
  if (EncapResponseStruct == NULL) {
    return RETURN_UNSUPPORTED;
  }
 
  Continue = FALSE;
  if (EncapResponseStruct->ProcessEncapResponse != NULL) {
    Status = EncapResponseStruct->ProcessEncapResponse (SpdmContext, EncapResponseSize, EncapResponse, &Continue);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }

  if (Continue) {
    ASSERT (EncapResponseStruct->ContinueGetEncapRequest != NULL);
    if (EncapResponseStruct->ContinueGetEncapRequest) {
      Status = EncapResponseStruct->ContinueGetEncapRequest (SpdmContext, EncapRequestSize, EncapRequest);
    } else {
      Status = RETURN_UNSUPPORTED;
    }
  } else {
    if (EncapResponseStruct->NextGetEncapRequest != NULL) {
      Status = EncapResponseStruct->NextGetEncapRequest (SpdmContext, EncapRequestSize, EncapRequest);
    } else {
      // Done
      *RequestId = 0;
      *EncapRequestSize = 0;
      SpdmContext->EncapContext.EncapState = SpdmEncapResponseStateNotStarted;
      return RETURN_SUCCESS;
    }
  }

  if (RETURN_ERROR(Status)) {
    return Status;
  }

  *RequestId = *RequestId + 1;
  if (!Continue) {
    SpdmContext->EncapContext.EncapState ++;
  }

  return RETURN_SUCCESS;
}

/**
  This function initializes the encapsulated state.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MutAuthRequested             Indicate of the MutAuthRequested through KEY_EXCHANGE or CHALLENG response.
**/
VOID
SpdmInitEncapState (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MutAuthRequested
  )
{
  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.EncapState = 0;
  if (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)) {
    SpdmContext->EncapContext.EncapState = 1;
  }
  SpdmContext->EncapContext.CertificateChainBuffer.BufferSize = 0;
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
  UINT8                                  RequestId;
  RETURN_STATUS                          Status;

  SpdmContext = Context;
  if (RequestSize != sizeof(SPDM_GET_ENCAPSULATED_REQUEST_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  //
  // Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);

  ASSERT (*ResponseSize > sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE));
  ZeroMem (Response, *ResponseSize);

  SpdmResponse = Response;
  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_ENCAPSULATED_REQUEST;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;

  EncapRequestSize = *ResponseSize - sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE);
  EncapRequest = SpdmResponse + 1;

  RequestId = 0;
  SpdmInitEncapState (Context, 0);
  Status = SpdmProcessEncapsulatedResponse (Context, &RequestId, 0, NULL, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  *ResponseSize = sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = RequestId;

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
  UINT8                                       RequestId;
  RETURN_STATUS                               Status;

  SpdmContext = Context;
  if (RequestSize <= sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  SpdmRequest = Request;
  SpdmRequestSize = RequestSize;

  EncapResponse = (SpdmRequest + 1);
  EncapResponseSize = SpdmRequestSize - sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST);
  RequestId = SpdmRequest->Header.Param1;

  ASSERT (*ResponseSize > sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE));
  ZeroMem (Response, *ResponseSize);

  SpdmResponse = Response;
  SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  SpdmResponse->Header.RequestResponseCode = SPDM_ENCAPSULATED_RESPONSE_ACK;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT;

  EncapRequestSize = *ResponseSize - sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE);
  EncapRequest = SpdmResponse + 1;

  RequestId = 0;
  Status = SpdmProcessEncapsulatedResponse (Context, &RequestId, EncapResponseSize, EncapResponse, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  *ResponseSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = RequestId;
  if (EncapRequestSize == 0) {
    SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
    if (SpdmContext->EncapContext.SlotNum != 0) {
      SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER;
      *ResponseSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + 1;
      *(UINT8 *)(SpdmResponse + 1) = SpdmContext->EncapContext.SlotNum;
    }
  }

  return RETURN_SUCCESS;
}
