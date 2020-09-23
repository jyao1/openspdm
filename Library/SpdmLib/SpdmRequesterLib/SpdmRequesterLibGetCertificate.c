/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               PortionLength;
  UINT16               RemainderLength;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_BLOCK_LEN];
} SPDM_CERTIFICATE_RESPONSE_MAX;

#pragma pack()

BOOLEAN
SpdmRequesterVerifyCertificateChain (
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
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (buffer too large) !!!\n"));
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
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (buffer too small) !!!\n"));
      return FALSE;
    }
    if (CompareMem ((UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN), RootCertHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (root hash mismatch) !!!\n"));
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
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL !!!\n"));
      return FALSE;
    }
    if (CompareMem (CertificateChain, CertBuffer, CertificateChainSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL !!!\n"));
      return FALSE;
    }
  }
  DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - PASS !!!\n"));
  SpdmContext->ConnectionInfo.PeerCertChainBufferSize = CertificateChainSize;
  CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, CertificateChain, CertificateChainSize);

  return TRUE;
}

/*
  Get CertificateChain in one slot returned from device.
*/
RETURN_STATUS
TrySpdmGetCertificate (
  IN     VOID                 *Context,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  )
{
  BOOLEAN                                   Result;
  RETURN_STATUS                             Status;
  SPDM_GET_CERTIFICATE_REQUEST              SpdmRequest;
  SPDM_CERTIFICATE_RESPONSE_MAX             SpdmResponse;
  UINTN                                     SpdmResponseSize;
  LARGE_MANAGED_BUFFER                      CertificateChainBuffer = {MAX_SPDM_MESSAGE_BUFFER_SIZE};
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_GET_DIGESTS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0)) {
    return RETURN_DEVICE_ERROR;
  }
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  do {
    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
      SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    } else {
      SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    }
    SpdmRequest.Header.RequestResponseCode = SPDM_GET_CERTIFICATE;
    SpdmRequest.Header.Param1 = SlotNum;
    SpdmRequest.Header.Param2 = 0;
    SpdmRequest.Offset = (UINT16)GetManagedBufferSize (&CertificateChainBuffer);
    SpdmRequest.Length = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
    DEBUG((DEBUG_INFO, "Request (Offset 0x%x, Size 0x%x):\n", SpdmRequest.Offset, SpdmRequest.Length));

    Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
    if (RETURN_ERROR(Status)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }

    //
    // Cache data
    //
    AppendManagedBuffer (&SpdmContext->Transcript.MessageB, &SpdmRequest, sizeof(SpdmRequest));

    SpdmResponseSize = sizeof(SpdmResponse);
    ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
    Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
    if (RETURN_ERROR(Status)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
      Status = SpdmHandleErrorResponseMain(SpdmContext, &SpdmContext->Transcript.MessageB, sizeof(SpdmRequest), &SpdmResponseSize, &SpdmResponse, SPDM_GET_CERTIFICATE, SPDM_CERTIFICATE, sizeof(SPDM_CERTIFICATE_RESPONSE_MAX));
      if (RETURN_ERROR(Status)) {
        goto Done;
      }
    } else if (SpdmResponse.Header.RequestResponseCode != SPDM_CERTIFICATE) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize > sizeof(SpdmResponse)) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.PortionLength > MAX_SPDM_CERT_CHAIN_BLOCK_LEN) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponse.Header.Param1 != SlotNum) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    if (SpdmResponseSize < sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse.PortionLength) {
      Status = RETURN_DEVICE_ERROR;
      goto Done;
    }
    SpdmResponseSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + SpdmResponse.PortionLength;
    //
    // Cache data
    //
    AppendManagedBuffer (&SpdmContext->Transcript.MessageB, &SpdmResponse, SpdmResponseSize);

    DEBUG((DEBUG_INFO, "Certificate (Offset 0x%x, Size 0x%x):\n", SpdmRequest.Offset, SpdmResponse.PortionLength));
    InternalDumpHex (SpdmResponse.CertChain, SpdmResponse.PortionLength);

    AppendManagedBuffer (&CertificateChainBuffer, SpdmResponse.CertChain, SpdmResponse.PortionLength);

  } while (SpdmResponse.RemainderLength != 0);

  Result = SpdmRequesterVerifyCertificateChain (SpdmContext, GetManagedBuffer(&CertificateChainBuffer), GetManagedBufferSize(&CertificateChainBuffer));
  if (!Result) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    Status = RETURN_SECURITY_VIOLATION;
    goto Done;
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;

  if (CertChainSize != NULL) {
    if (*CertChainSize < GetManagedBufferSize(&CertificateChainBuffer)) {
      *CertChainSize = GetManagedBufferSize(&CertificateChainBuffer);
      return RETURN_BUFFER_TOO_SMALL;
    }
    *CertChainSize = GetManagedBufferSize(&CertificateChainBuffer);
    if (CertChain != NULL) {
      CopyMem (
        CertChain,
        GetManagedBuffer(&CertificateChainBuffer),
        GetManagedBufferSize(&CertificateChainBuffer)
        );
    }
  }
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CERTIFICATE_RECEIVE_FLAG;
  Status = RETURN_SUCCESS;
Done:
  return Status;
}

RETURN_STATUS
EFIAPI
SpdmGetCertificate (
  IN     VOID                 *Context,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain
  )
{
  SPDM_DEVICE_CONTEXT    *SpdmContext;
  UINTN                   Retry;
  RETURN_STATUS           Status;
  
  SpdmContext = Context;
  Retry = SpdmContext->RetryTimes;
  while(Retry-- != 0) {
    Status = TrySpdmGetCertificate(SpdmContext, SlotNum, CertChainSize, CertChain);
    if (RETURN_NO_RESPONSE != Status)
      return Status;
  }

  return Status;
}

