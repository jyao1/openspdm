/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  Get the SPDM encapsulated CHALLENGE request.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapRequestSize             Size in bytes of the encapsulated request data.
                                       On input, it means the size in bytes of encapsulated request data buffer.
                                       On output, it means the size in bytes of copied encapsulated request data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired encapsulated request data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  EncapRequest                 A pointer to the encapsulated request data.

  @retval RETURN_SUCCESS               The encapsulated request is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGetEncapReqestChallenge (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_CHALLENGE_REQUEST                  *SpdmRequest;
  RETURN_STATUS                           Status;

  ASSERT (*EncapRequestSize >= sizeof(SPDM_CHALLENGE_REQUEST));
  *EncapRequestSize = sizeof(SPDM_CHALLENGE_REQUEST);

  SpdmRequest = EncapRequest;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest->Header.RequestResponseCode = SPDM_CHALLENGE;
  SpdmRequest->Header.Param1 = SpdmContext->EncapContext.SlotNum;
  SpdmRequest->Header.Param2 = SpdmContext->EncapContext.MeasurementHashType;
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, SpdmRequest->Nonce);
  DEBUG((DEBUG_INFO, "Encap ClientNonce - "));
  InternalDumpData (SpdmRequest->Nonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));

  //
  // Cache data
  //
  Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, SpdmRequest, *EncapRequestSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated CHALLENGE_AUTH response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  EncapResponseSize            Size in bytes of the encapsulated response data.
  @param  EncapResponse                A pointer to the encapsulated response data.
  @param  Continue                     Indicate if encapsulated communication need continue.

  @retval RETURN_SUCCESS               The encapsulated response is processed.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseChallengeAuth (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  )
{
  BOOLEAN                                   Result;
  SPDM_CHALLENGE_AUTH_RESPONSE              *SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT8                                     *Ptr;
  VOID                                      *CertChainHash;
  UINTN                                     HashSize;
  VOID                                      *ServerNonce;
  VOID                                      *MeasurementSummaryHash;
  UINT16                                    OpaqueLength;
  VOID                                      *Opaque;
  VOID                                      *Signature;
  UINTN                                     SignatureSize;
  SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE    AuthAttribute;
  RETURN_STATUS                             Status;

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmResponse = EncapResponse;
  SpdmResponseSize = EncapResponseSize;
  if (SpdmResponseSize < sizeof(SPDM_CHALLENGE_AUTH_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  if (SpdmResponse->Header.RequestResponseCode != SPDM_CHALLENGE_AUTH) {
    return RETURN_DEVICE_ERROR;
  }
  *(UINT8 *)&AuthAttribute = SpdmResponse->Header.Param1;
  if (SpdmContext->EncapContext.SlotNum == 0xFF) {
    if (AuthAttribute.SlotNum != 0xF) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmResponse->Header.Param2 != 0) {
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (AuthAttribute.SlotNum != SpdmContext->EncapContext.SlotNum) {
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmResponse->Header.Param2 != (1 << SpdmContext->EncapContext.SlotNum)) {
      return RETURN_DEVICE_ERROR;
    }
  }
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  SignatureSize = GetSpdmReqAsymSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);

  if (SpdmResponseSize <= sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
                          HashSize +
                          SPDM_NONCE_SIZE +
                          HashSize +
                          sizeof(UINT16)) {
    return RETURN_DEVICE_ERROR;
  }

  Ptr = (VOID *)(SpdmResponse + 1);

  CertChainHash = Ptr;
  Ptr += HashSize;
  DEBUG((DEBUG_INFO, "Encap CertChainHash (0x%x) - ", HashSize));
  InternalDumpData (CertChainHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  Result = SpdmVerifyCertificateChainHash (SpdmContext, CertChainHash, HashSize);
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  ServerNonce = Ptr;
  DEBUG((DEBUG_INFO, "Encap ServerNonce (0x%x) - ", SPDM_NONCE_SIZE));
  InternalDumpData (ServerNonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));
  Ptr += SPDM_NONCE_SIZE;

  MeasurementSummaryHash = Ptr;
  Ptr += HashSize;
  DEBUG((DEBUG_INFO, "Encap MeasurementSummaryHash (0x%x) - ", HashSize));
  InternalDumpData (MeasurementSummaryHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  OpaqueLength = *(UINT16 *)Ptr;
  Ptr += sizeof(UINT16);

  if (SpdmResponseSize < sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
                         HashSize +
                         SPDM_NONCE_SIZE +
                         HashSize +
                         sizeof(UINT16) +
                         OpaqueLength +
                         SignatureSize) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
                     HashSize +
                     SPDM_NONCE_SIZE +
                     HashSize +
                     sizeof(UINT16) +
                     OpaqueLength +
                     SignatureSize;
  Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, SpdmResponse, SpdmResponseSize - SignatureSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  Opaque = Ptr;
  Ptr += OpaqueLength;
  DEBUG((DEBUG_INFO, "Encap Opaque (0x%x):\n", OpaqueLength));
  InternalDumpHex (Opaque, OpaqueLength);

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Encap Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Result = SpdmVerifyChallengeAuthSignature (SpdmContext, FALSE, Signature, SignatureSize);
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFICATE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_SUCCESS;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;

  *Continue = FALSE;

  return RETURN_SUCCESS;
}
