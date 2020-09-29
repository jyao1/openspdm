/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

typedef
RETURN_STATUS
(EFIAPI *SPDM_GET_ENCAP_REQUEST) (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  );

typedef
RETURN_STATUS
(EFIAPI *SPDM_PROCESS_ENCAP_RESPONSE) (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
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

SPDM_ENCAP_RESPONSE_STRUCT *
SpdmGetEncapStructViaState (
  IN     SPDM_DEVICE_CONTEXT             *SpdmContext,
  IN     BOOLEAN                         IsSession,
  IN     SPDM_ENCAP_RESPONSE_STATE       EncapState
  )
{
  UINTN                Index;

  if (IsSession) {
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

RETURN_STATUS
SpdmProcessEncapsulatedResponse (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     BOOLEAN              IsSession,
  IN OUT UINT8                *RequestId,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  RETURN_STATUS               Status;
  BOOLEAN                     Continue;
  SPDM_ENCAP_RESPONSE_STRUCT  *EncapResponseStruct;

  EncapResponseStruct = SpdmGetEncapStructViaState (SpdmContext, IsSession, SpdmContext->EncapContext.EncapState);
  ASSERT (EncapResponseStruct != NULL);
  if (EncapResponseStruct == NULL) {
    return RETURN_UNSUPPORTED;
  }
 
  Continue = FALSE;
  if (EncapResponseStruct->ProcessEncapResponse != NULL) {
    Status = EncapResponseStruct->ProcessEncapResponse (SpdmContext, EncapLastResponseSize, EncapLastResponse, &Continue);
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

VOID
SpdmInitEncapEnv (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MutAuthRequested
  )
{
  ASSERT ((MutAuthRequested == 0) ||
          (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST)) ||
          (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)));
  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.EncapState = 0;
  SpdmContext->EncapContext.SlotNum = 0;
  SpdmContext->EncapContext.MeasurementHashType = SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH;
  SpdmContext->EncapContext.CertificateChainBuffer.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->EncapContext.CertificateChainBuffer.BufferSize = 0;
  if (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)) {
    SpdmContext->EncapContext.EncapState = 1;
  }
}

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedRequestEx (
  IN     VOID                 *Context,
  IN     BOOLEAN              IsSession,
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
  SpdmInitEncapEnv (Context, 0);
  Status = SpdmProcessEncapsulatedResponse (Context, IsSession, &RequestId, 0, NULL, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  *ResponseSize = sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = RequestId;

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedResponseAckEx (
  IN     VOID                 *Context,
  IN     BOOLEAN              IsSession,
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
  VOID                                        *EncapLastResponse;
  UINTN                                       EncapLastResponseSize;
  VOID                                        *EncapRequest;
  UINTN                                       EncapRequestSize;
  UINT8                                       RequestId;
  RETURN_STATUS                               Status;

  SpdmContext = Context;
  SpdmRequest = Request;
  if (RequestSize <= sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SpdmRequestSize = RequestSize;

  EncapLastResponse = (SpdmRequest + 1);
  EncapLastResponseSize = SpdmRequestSize - sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST);
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
  Status = SpdmProcessEncapsulatedResponse (Context, IsSession, &RequestId, EncapLastResponseSize, EncapLastResponse, &EncapRequestSize, EncapRequest);
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  *ResponseSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + EncapRequestSize;
  SpdmResponse->Header.Param1 = RequestId;
  if (EncapRequestSize == 0) {
    SpdmResponse->Header.Param2 = SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT;
  }

  return RETURN_SUCCESS;
}


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
  return SpdmGetResponseEncapsulatedRequestEx (
           Context,
           FALSE,
           RequestSize,
           Request,
           ResponseSize,
           Response
           );
}

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
  return SpdmGetResponseEncapsulatedResponseAckEx (
           Context,
           FALSE,
           RequestSize,
           Request,
           ResponseSize,
           Response
           );
}

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedRequestSession (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  return SpdmGetResponseEncapsulatedRequestEx (
           Context,
           TRUE,
           RequestSize,
           Request,
           ResponseSize,
           Response
           );
}

RETURN_STATUS
EFIAPI
SpdmGetResponseEncapsulatedResponseAckSession (
  IN     VOID                 *Context,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  return SpdmGetResponseEncapsulatedResponseAckEx (
           Context,
           TRUE,
           RequestSize,
           Request,
           ResponseSize,
           Response
           );
}

