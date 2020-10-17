/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

/**
  This function verifies the integrity of certificate chain.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertificateChain             The certificate chain data buffer.
  @param  CertificateChainSize         Size in bytes of the certificate chain data buffer.

  @retval TRUE  certificate chain integrity verification pass.
  @retval FALSE certificate chain integrity verification fail.
**/
BOOLEAN
SpdmEncapRequesterVerifyCertificateChainData (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChain,
  UINTN                           CertificateChainSize
  )
{
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINT8                                     *RootCertBuffer;
  UINTN                                     RootCertBufferSize;
  UINTN                                     HashSize;
  UINT8                                     CalcRootCertHash[MAX_HASH_SIZE];
  UINT8                                     *LeafCertBuffer;
  UINTN                                     LeafCertBufferSize;

  HashSize = GetSpdmHashSize (SpdmContext);

  if (CertificateChainSize > MAX_SPDM_MESSAGE_BUFFER_SIZE) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (buffer too large) !!!\n"));
    return FALSE;
  }

  if (CertificateChainSize <= sizeof(SPDM_CERT_CHAIN) + HashSize) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (buffer too small) !!!\n"));
    return FALSE;
  }

  CertBuffer = (UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = CertificateChainSize - sizeof(SPDM_CERT_CHAIN) - HashSize;
  if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, 0, &RootCertBuffer, &RootCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get root certificate failed)!!!\n"));
    return FALSE;
  }

  SpdmHashAll (SpdmContext, RootCertBuffer, RootCertBufferSize, CalcRootCertHash);
  if (CompareMem ((UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN), CalcRootCertHash, HashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (cert root hash mismatch) !!!\n"));
    return FALSE;
  }

  if (!X509VerifyCertChain (RootCertBuffer, RootCertBufferSize, CertBuffer, CertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (cert chain verify failed)!!!\n"));
    return FALSE;
  }

  if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, -1, &LeafCertBuffer, &LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
    return FALSE;
  }

  if(!SpdmX509CertificateCheck (LeafCertBuffer, LeafCertBufferSize)) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (leaf certificate check failed)!!!\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  This function verifies the certificate chain.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertificateChain             The certificate chain data buffer.
  @param  CertificateChainSize         Size in bytes of the certificate chain data buffer.

  @retval TRUE  certificate chain verification pass.
  @retval FALSE certificate chain verification fail.
**/
BOOLEAN
SpdmEncapRequesterVerifyCertificateChain (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChain,
  UINTN                           CertificateChainSize
  )
{
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINTN                                     HashSize;
  UINT8                                     *RootCertHash;
  UINTN                                     RootCertHashSize;
  BOOLEAN                                   Result;

  Result = SpdmEncapRequesterVerifyCertificateChainData(SpdmContext, CertificateChain, CertificateChainSize);
  if (!Result) {
    return FALSE;
  }

  RootCertHash = SpdmContext->LocalContext.PeerRootCertHashProvision;
  RootCertHashSize = SpdmContext->LocalContext.PeerRootCertHashProvisionSize;
  CertBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;

  if ((RootCertHash != NULL) && (RootCertHashSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext);
    if (RootCertHashSize != HashSize) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (hash size mismatch) !!!\n"));
      return FALSE;
    }
    if (CompareMem ((UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN), RootCertHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (root hash mismatch) !!!\n"));
      return FALSE;
    }
  } else if ((CertBuffer != NULL) && (CertBufferSize != 0)) {
    if (CertBufferSize != CertificateChainSize) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL !!!\n"));
      return FALSE;
    }
    if (CompareMem (CertificateChain, CertBuffer, CertificateChainSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - PASS !!!\n"));
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = CertificateChainSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, CertificateChain, CertificateChainSize);

  return TRUE;
}

/**
  Get the SPDM encapsulated GET_CERTIFICATE request.

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
SpdmGetEncapReqestGetCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_GET_CERTIFICATE_REQUEST                  *SpdmRequest;

  ASSERT (*EncapRequestSize >= sizeof(SPDM_GET_CERTIFICATE_REQUEST));
  *EncapRequestSize = sizeof(SPDM_GET_CERTIFICATE_REQUEST);

  SpdmRequest = EncapRequest;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest->Header.RequestResponseCode = SPDM_GET_CERTIFICATE;
  SpdmRequest->Header.Param1 = SpdmContext->EncapContext.SlotNum;
  SpdmRequest->Header.Param2 = 0;
  SpdmRequest->Offset = (UINT16)GetManagedBufferSize (&SpdmContext->EncapContext.CertificateChainBuffer);
  SpdmRequest->Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  DEBUG((DEBUG_INFO, "Request (Offset 0x%x, Size 0x%x):\n", SpdmRequest->Offset, SpdmRequest->Length));

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutB, SpdmRequest, *EncapRequestSize);

  return RETURN_SUCCESS;
}

/**
  Process the SPDM encapsulated CERTIFICATE response.

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
SpdmProcessEncapResponseCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapResponseSize,
  IN     VOID                 *EncapResponse,
  OUT    BOOLEAN              *Continue
  )
{
  SPDM_CERTIFICATE_RESPONSE             *SpdmResponse;
  UINTN                                 SpdmResponseSize;
  BOOLEAN                               Result;

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  SpdmResponse = EncapResponse;
  SpdmResponseSize = EncapResponseSize;
  if (EncapResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }

  if (SpdmResponse->Header.RequestResponseCode != SPDM_CERTIFICATE) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->PortionLength > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->Header.Param1 != SpdmContext->EncapContext.SlotNum) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse->PortionLength) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse->PortionLength;
  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageMutB, SpdmResponse, SpdmResponseSize);

  DEBUG((DEBUG_INFO, "Certificate (Offset 0x%x, Size 0x%x):\n", GetManagedBufferSize (&SpdmContext->EncapContext.CertificateChainBuffer), SpdmResponse->PortionLength));
  InternalDumpHex ((VOID *)(SpdmResponse + 1), SpdmResponse->PortionLength);

  AppendManagedBuffer (&SpdmContext->EncapContext.CertificateChainBuffer, (VOID *)(SpdmResponse + 1), SpdmResponse->PortionLength);

  if (SpdmResponse->RemainderLength != 0) {
    *Continue = TRUE;
    return RETURN_SUCCESS;
  }

  *Continue = FALSE;
  Result = SpdmEncapRequesterVerifyCertificateChain (SpdmContext, GetManagedBuffer(&SpdmContext->EncapContext.CertificateChainBuffer), GetManagedBufferSize(&SpdmContext->EncapContext.CertificateChainBuffer));
  if (!Result) {
    SpdmContext->EncapContext.ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->EncapContext.ErrorState = SPDM_STATUS_SUCCESS;

  return RETURN_SUCCESS;
}
