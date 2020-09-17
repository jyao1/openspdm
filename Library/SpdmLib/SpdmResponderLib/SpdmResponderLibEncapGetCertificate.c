/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
  UINT8                                     *RootCertBuffer;
  UINTN                                     RootCertBufferSize;

  if (CertificateChainSize > MAX_SPDM_MESSAGE_BUFFER_SIZE) {
    DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (buffer too large) !!!\n"));
    return FALSE;
  }

  RootCertHash = SpdmContext->LocalContext.PeerRootCertHashVarBuffer;
  RootCertHashSize = SpdmContext->LocalContext.PeerRootCertHashVarBufferSize;
  CertBuffer = SpdmContext->LocalContext.PeerCertChainVarBuffer;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainVarBufferSize;

  if ((RootCertHash != NULL) && (RootCertHashSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext);
    ASSERT (RootCertHashSize == HashSize);
    if (CertificateChainSize <= sizeof(SPDM_CERT_CHAIN) + HashSize) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (buffer too small) !!!\n"));
      return FALSE;
    }
    if (CompareMem ((UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN), RootCertHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! EncapVerifyCertificateChain - FAIL (root hash mismatch) !!!\n"));
      return FALSE;
    }
    // verify the CertChain
    CertBuffer = (UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertBufferSize = CertificateChainSize - sizeof(SPDM_CERT_CHAIN) - HashSize;
    if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, 0, &RootCertBuffer, &RootCertBufferSize)) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get root certificate failed)!!!\n"));
      return FALSE;
    }
    if (!X509VerifyCertChain (RootCertBuffer, RootCertBufferSize, CertBuffer, CertBufferSize)) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (cert chain verify failed)!!!\n"));
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

RETURN_STATUS
EFIAPI
SpdmGetEncapReqestGetCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN OUT UINTN                *EncapRequestSize,
     OUT VOID                 *EncapRequest
  )
{
  SPDM_GET_CERTIFICATE_REQUEST                  *SpdmRequest;

  ASSERT (*EncapRequestSize >= sizeof(SPDM_GET_CERTIFICATE_REQUEST) - 1);
  *EncapRequestSize = sizeof(SPDM_GET_CERTIFICATE_REQUEST) - 1;

  SpdmRequest = (VOID *)((UINT8 *)EncapRequest - 1);

  SpdmRequest->Header.RequestResponseCode = SPDM_GET_CERTIFICATE;
  SpdmRequest->Header.Param1 = SpdmContext->EncapContext.SlotNum;
  SpdmRequest->Header.Param2 = 0;
  SpdmRequest->Offset = (UINT16)GetManagedBufferSize (&SpdmContext->EncapContext.CertificateChainBuffer);
  SpdmRequest->Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  DEBUG((DEBUG_INFO, "Request (Offset 0x%x, Size 0x%x):\n", SpdmRequest->Offset, SpdmRequest->Length));

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmProcessEncapResponseCertificate (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINTN                EncapLastResponseSize,
  IN     VOID                 *EncapLastResponse,
  OUT    BOOLEAN              *Continue
  )
{
  SPDM_CERTIFICATE_RESPONSE             *SpdmResponse;
  BOOLEAN                               Result;

  if (EncapLastResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE) - 1) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponse = (VOID *)((UINT8 *)EncapLastResponse - 1);

  if (SpdmResponse->Header.RequestResponseCode != SPDM_CERTIFICATE) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->PortionLength > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse->Header.Param1 != SpdmContext->EncapContext.SlotNum) {
    return RETURN_DEVICE_ERROR;
  }
  if (EncapLastResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE) - 1 + SpdmResponse->PortionLength) {
    return RETURN_DEVICE_ERROR;
  }
  EncapLastResponseSize = sizeof(SPDM_CERTIFICATE_RESPONSE) - 1 + SpdmResponse->PortionLength;

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
    return RETURN_SECURITY_VIOLATION;
  }

  return RETURN_SUCCESS;
}
