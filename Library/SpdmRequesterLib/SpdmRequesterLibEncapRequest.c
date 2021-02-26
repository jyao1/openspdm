/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

typedef struct {
  UINT8                          RequestResponseCode;
  SPDM_GET_ENCAP_RESPONSE_FUNC   GetEncapResponseFunc;
} SPDM_GET_ENCAP_RESPONSE_STRUCT;

SPDM_GET_ENCAP_RESPONSE_STRUCT  mSpdmGetEncapResponseStruct[] = {
  {SPDM_GET_DIGESTS,            SpdmGetEncapResponseDigest},
  {SPDM_GET_CERTIFICATE,        SpdmGetEncapResponseCertificate},
  {SPDM_CHALLENGE,              SpdmGetEncapResponseChallengeAuth},
  {SPDM_KEY_UPDATE,             SpdmGetEncapResponseKeyUpdate},
};

/**
  Register an SPDM encapsulated message process function.

  If the default encapsulated message process function cannot handle the encapsulated message,
  this function will be invoked.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  GetEncapResponseFunc         The function to process the encapsuled message.
**/
VOID
EFIAPI
SpdmRegisterGetEncapResponseFunc (
  IN  VOID                          *Context,
  IN  SPDM_GET_ENCAP_RESPONSE_FUNC  GetEncapResponseFunc
  )
{
  SPDM_DEVICE_CONTEXT     *SpdmContext;

  SpdmContext = Context;
  SpdmContext->GetEncapResponseFunc = (UINTN)GetEncapResponseFunc;

  return ;
}

/**
  Return the GET_ENCAP_RESPONSE function via request code.

  @param  RequestCode                  The SPDM request code.

  @return GET_ENCAP_RESPONSE function according to the request code.
**/
SPDM_GET_ENCAP_RESPONSE_FUNC
SpdmGetEncapResponseFuncViaRequestCode (
  IN     UINT8                   RequestResponseCode
  )
{
  UINTN                Index;

  for (Index = 0; Index < sizeof(mSpdmGetEncapResponseStruct)/sizeof(mSpdmGetEncapResponseStruct[0]); Index++) {
    if (RequestResponseCode == mSpdmGetEncapResponseStruct[Index].RequestResponseCode) {
      return mSpdmGetEncapResponseStruct[Index].GetEncapResponseFunc;
    }
  }
  return NULL;
}

/**
  This function processes encapsulated request.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapRequestSize             Size in bytes of the request data buffer.
  @param  EncapRequest                 A pointer to a destination buffer to store the request.
  @param  EncapResponseSize            Size in bytes of the response data buffer.
  @param  EncapResponse                A pointer to a destination buffer to store the response.

  @retval RETURN_SUCCESS               The SPDM response is processed successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM response is sent to the device.
**/
RETURN_STATUS
SpdmProcessEncapsulatedRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapRequestSize,
  IN     VOID                 *EncapRequest,
  IN OUT UINTN                *EncapResponseSize,
     OUT VOID                 *EncapResponse
  )
{
  SPDM_GET_ENCAP_RESPONSE_FUNC    GetEncapResponseFunc;
  RETURN_STATUS                   Status;
  SPDM_MESSAGE_HEADER             *SpdmRequester;

  SpdmRequester = EncapRequest;
  if (EncapRequestSize < sizeof(SPDM_MESSAGE_HEADER)) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequester->RequestResponseCode, EncapResponseSize, EncapResponse);
  }

  GetEncapResponseFunc = SpdmGetEncapResponseFuncViaRequestCode (SpdmRequester->RequestResponseCode);
  if (GetEncapResponseFunc == NULL) {
    GetEncapResponseFunc = (SPDM_GET_ENCAP_RESPONSE_FUNC)SpdmContext->GetEncapResponseFunc;
  }
  if (GetEncapResponseFunc != NULL) {
    Status = GetEncapResponseFunc (SpdmContext, EncapRequestSize, EncapRequest, EncapResponseSize, EncapResponse);
  } else {
    Status = RETURN_NOT_FOUND;
  }
  if (Status != RETURN_SUCCESS) {
    SpdmGenerateEncapErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNSUPPORTED_REQUEST, SpdmRequester->RequestResponseCode, EncapResponseSize, EncapResponse);
  }

  return RETURN_SUCCESS;
}

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicate if the encapsulated request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
  @param  MutAuthRequested             Indicate of the MutAuthRequested through KEY_EXCHANGE or CHALLENG response.
  @param  ReqSlotIdParam               ReqSlotIdParam from the RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
SpdmEncapsulatedRequest (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINT8                MutAuthRequested,
     OUT UINT8                *ReqSlotIdParam
  )
{
  RETURN_STATUS                               Status;
  UINT8                                       Request[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                       SpdmRequestSize;
  SPDM_GET_ENCAPSULATED_REQUEST_REQUEST       *SpdmGetEncapsulatedRequestRequest;
  SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST  *SpdmDeliverEncapsulatedResponseRequest;
  UINT8                                       Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                       SpdmResponseSize;
  SPDM_ENCAPSULATED_REQUEST_RESPONSE          *SpdmEncapsulatedRequestResponse;
  SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE     *SpdmEncapsulatedResponseAckResponse;
  SPDM_SESSION_INFO                           *SessionInfo;
  UINT8                                       RequestId;
  VOID                                        *EncapsulatedRequest;
  UINTN                                       EncapsulatedRequestSize;
  VOID                                        *EncapsulatedResponse;
  UINTN                                       EncapsulatedResponseSize;
  SPDM_GET_DIGESTS_REQUEST                    GetDigests;
  
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP)) {
    return RETURN_UNSUPPORTED;
  }

  if (SessionId != NULL) {
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    if (SessionInfo == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }
    ASSERT ((MutAuthRequested == 0) ||
            (MutAuthRequested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) ||
            (MutAuthRequested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS));
  } else {
    ASSERT (MutAuthRequested == 0);
  }

  //
  // Cache
  //
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);

  if (SessionId == NULL) {
    SpdmContext->LastSpdmRequestSessionIdValid = FALSE;
    SpdmContext->LastSpdmRequestSessionId = 0;
  } else {
    SpdmContext->LastSpdmRequestSessionIdValid = TRUE;
    SpdmContext->LastSpdmRequestSessionId = *SessionId;
  }

  if (MutAuthRequested == SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS) {
    GetDigests.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    GetDigests.Header.RequestResponseCode = SPDM_GET_DIGESTS;
    GetDigests.Header.Param1 = 0;
    GetDigests.Header.Param2 = 0;
    EncapsulatedRequest = (VOID *)&GetDigests;
    EncapsulatedRequestSize = sizeof(GetDigests);

    RequestId = 0;
  } else {
    SpdmGetEncapsulatedRequestRequest = (VOID *)Request;
    SpdmGetEncapsulatedRequestRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmGetEncapsulatedRequestRequest->Header.RequestResponseCode = SPDM_GET_ENCAPSULATED_REQUEST;
    SpdmGetEncapsulatedRequestRequest->Header.Param1 = 0;
    SpdmGetEncapsulatedRequestRequest->Header.Param2 = 0;
    SpdmRequestSize = sizeof(SPDM_GET_ENCAPSULATED_REQUEST_REQUEST);
    Status = SpdmSendSpdmRequest (SpdmContext, SessionId, SpdmRequestSize, SpdmGetEncapsulatedRequestRequest);
    if (RETURN_ERROR(Status)) {
      return RETURN_DEVICE_ERROR;
    }

    SpdmEncapsulatedRequestResponse = (VOID *)Response;
    SpdmResponseSize = sizeof(Response);
    ZeroMem (&Response, sizeof(Response));
    Status = SpdmReceiveSpdmResponse (SpdmContext, SessionId, &SpdmResponseSize, SpdmEncapsulatedRequestResponse);
    if (RETURN_ERROR(Status)) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmEncapsulatedRequestResponse->Header.RequestResponseCode != SPDM_ENCAPSULATED_REQUEST) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmResponseSize < sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE)) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmResponseSize == sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE)) {
      //
      // Done
      //
      return RETURN_SUCCESS;
    }
    RequestId = SpdmEncapsulatedRequestResponse->Header.Param1;

    EncapsulatedRequest = (VOID *)(SpdmEncapsulatedRequestResponse + 1);
    EncapsulatedRequestSize = SpdmResponseSize - sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE);
  }

  while (TRUE) {
    //
    // Process Request
    //
    SpdmDeliverEncapsulatedResponseRequest = (VOID *)Request;
    SpdmDeliverEncapsulatedResponseRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmDeliverEncapsulatedResponseRequest->Header.RequestResponseCode = SPDM_DELIVER_ENCAPSULATED_RESPONSE;
    SpdmDeliverEncapsulatedResponseRequest->Header.Param1 = RequestId;
    SpdmDeliverEncapsulatedResponseRequest->Header.Param2 = 0;
    EncapsulatedResponse = (VOID *)(SpdmDeliverEncapsulatedResponseRequest + 1);
    EncapsulatedResponseSize = sizeof(Request) - sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST);

    Status = SpdmProcessEncapsulatedRequest (SpdmContext, EncapsulatedRequestSize, EncapsulatedRequest, &EncapsulatedResponseSize, EncapsulatedResponse);
    if (RETURN_ERROR(Status)) {
      return RETURN_DEVICE_ERROR;
    }

    SpdmRequestSize = sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST) + EncapsulatedResponseSize;
    Status = SpdmSendSpdmRequest (SpdmContext, SessionId, SpdmRequestSize, SpdmDeliverEncapsulatedResponseRequest);
    if (RETURN_ERROR(Status)) {
      return RETURN_DEVICE_ERROR;
    }
    
    SpdmEncapsulatedResponseAckResponse = (VOID *)Response;
    SpdmResponseSize = sizeof(Response);
    ZeroMem (&Response, sizeof(Response));
    Status = SpdmReceiveSpdmResponse (SpdmContext, SessionId, &SpdmResponseSize, SpdmEncapsulatedResponseAckResponse);
    if (RETURN_ERROR(Status)) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmEncapsulatedResponseAckResponse->Header.RequestResponseCode != SPDM_ENCAPSULATED_RESPONSE_ACK) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmResponseSize < sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE)) {
      return RETURN_DEVICE_ERROR;
    }
    switch (SpdmEncapsulatedResponseAckResponse->Header.Param2) {
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
      if (SpdmResponseSize == sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE)) {
        return RETURN_SUCCESS;
      } else {
        return RETURN_DEVICE_ERROR;
      }
      break;
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
      break;
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER:
      if (SpdmResponseSize >= sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + sizeof(UINT8)) {
        if ((ReqSlotIdParam != NULL) && (*ReqSlotIdParam == 0)) {
          *ReqSlotIdParam = *(UINT8 *)(SpdmEncapsulatedResponseAckResponse + 1);
          if (*ReqSlotIdParam >= SpdmContext->LocalContext.SlotCount) {
            return RETURN_DEVICE_ERROR;
          }
        }
        return RETURN_SUCCESS;
      } else {
        return RETURN_DEVICE_ERROR;
      }
      break;
    default:
      return RETURN_DEVICE_ERROR;
    }
    RequestId = SpdmEncapsulatedResponseAckResponse->Header.Param1;

    EncapsulatedRequest = (VOID *)(SpdmEncapsulatedResponseAckResponse + 1);
    EncapsulatedRequestSize = SpdmResponseSize - sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE);
  }

  return RETURN_SUCCESS;
}

/**
  This function executes a series of SPDM encapsulated requests and receives SPDM encapsulated responses.

  This function starts with the first encapsulated request (such as GET_ENCAPSULATED_REQUEST)
  and ends with last encapsulated response (such as RESPONSE_PAYLOAD_TYPE_ABSENT or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER).

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicate if the encapsulated request is a secured message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.

  @retval RETURN_SUCCESS               The SPDM Encapsulated requests are sent and the responses are received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmSendReceiveEncapsulatedRequest (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId
  )
{
  return SpdmEncapsulatedRequest (SpdmContext, SessionId, 0, NULL);
}