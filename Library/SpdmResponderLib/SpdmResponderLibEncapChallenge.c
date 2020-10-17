/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  This function verifies the certificate chain hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertificateChainHash         The certificate chain hash data buffer.
  @param  CertificateChainHashSize     Size in bytes of the certificate chain hash data buffer.

  @retval TRUE  hash verification pass.
  @retval FALSE hash verification fail.
**/
BOOLEAN
SpdmEncapRequesterVerifyCertificateChainHash (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChainHash,
  UINTN                           CertificateChainHashSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;

  CertBuffer = SpdmContext->ConnectionInfo.PeerCertChainBuffer;
  CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize;
  if (CertBufferSize == 0) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext);

  SpdmHashAll (SpdmContext, CertBuffer, CertBufferSize, CertBufferHash);

  if (HashSize != CertificateChainHashSize) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChainHash - FAIL !!!\n"));
    return FALSE;
  }
  if (CompareMem (CertificateChainHash, CertBufferHash, CertificateChainHashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChainHash - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainHash - PASS !!!\n"));
  return TRUE;
}

/**
  This function verifies the challenge signature based upon M1M2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmEncapRequesterVerifyChallengeSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  UINTN                           SignDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;

  HashSize = GetSpdmHashSize (SpdmContext);

  DEBUG((DEBUG_INFO, "Encap MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "Encap MessageB Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));

  DEBUG((DEBUG_INFO, "Encap MessageC Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&SpdmContext->Transcript.M1M2), GetManagedBufferSize(&SpdmContext->Transcript.M1M2), HashData);
  DEBUG((DEBUG_INFO, "Encap M1M2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }

  CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainBuffer, CertChainBufferSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymGetPublicKeyFromX509 (SpdmContext, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymVerify (
             SpdmContext,
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  SpdmReqAsymFree (SpdmContext, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyChallengeSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! EncapVerifyChallengeSignature - PASS !!!\n"));

  return TRUE;
}

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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, SpdmRequest, *EncapRequestSize);

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
  HashSize = GetSpdmHashSize (SpdmContext);
  SignatureSize = GetSpdmReqAsymSize (SpdmContext);

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
  Result = SpdmEncapRequesterVerifyCertificateChainHash (SpdmContext, CertChainHash, HashSize);
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, SpdmResponse, SpdmResponseSize - SignatureSize);
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutB), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutB));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutC), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutC));

  Opaque = Ptr;
  Ptr += OpaqueLength;
  DEBUG((DEBUG_INFO, "Encap Opaque (0x%x):\n", OpaqueLength));
  InternalDumpHex (Opaque, OpaqueLength);

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Encap Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Result = SpdmEncapRequesterVerifyChallengeSignature (SpdmContext, Signature, SignatureSize);
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_SUCCESS;

  *Continue = FALSE;

  return RETURN_SUCCESS;
}
