/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

BOOLEAN
SpdmCalculateM1M2Hash (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
  IN     BOOLEAN                IsMut,
     OUT VOID                   *HashData
  )
{
  RETURN_STATUS                 Status;
  UINT32                        HashSize;
  LARGE_MANAGED_BUFFER          M1M2;

  InitManagedBuffer (&M1M2, MAX_SPDM_MESSAGE_BUFFER_SIZE);

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (IsMut) {

    DEBUG((DEBUG_INFO, "MessageMutB Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageMutB), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutB));
    Status = AppendManagedBuffer (&M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutB), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutB));
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    DEBUG((DEBUG_INFO, "MessageMutC Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageMutC), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutC));
    Status = AppendManagedBuffer (&M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageMutC), GetManagedBufferSize(&SpdmContext->Transcript.MessageMutC));
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&M1M2), GetManagedBufferSize(&M1M2), HashData);
    DEBUG((DEBUG_INFO, "M1M2 Mut Hash - "));
    InternalDumpData (HashData, HashSize);
    DEBUG((DEBUG_INFO, "\n"));

  } else {

    DEBUG((DEBUG_INFO, "MessageA Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    Status = AppendManagedBuffer (&M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    DEBUG((DEBUG_INFO, "MessageB Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));
    Status = AppendManagedBuffer (&M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    DEBUG((DEBUG_INFO, "MessageC Data :\n"));
    InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));
    Status = AppendManagedBuffer (&M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&M1M2), GetManagedBufferSize(&M1M2), HashData);
    DEBUG((DEBUG_INFO, "M1M2 Hash - "));
    InternalDumpData (HashData, HashSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  return TRUE;
}

BOOLEAN
SpdmCalculateL1L2Hash (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
     OUT VOID                   *HashData
  )
{
  UINT32                        HashSize;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  DEBUG((DEBUG_INFO, "MessageM Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageM), GetManagedBufferSize(&SpdmContext->Transcript.MessageM));

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&SpdmContext->Transcript.MessageM), GetManagedBufferSize(&SpdmContext->Transcript.MessageM), HashData);
  DEBUG((DEBUG_INFO, "L1L2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  return TRUE;
}

/**
  This function generates the certificate chain hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotIndex                    The slot index of the certificate chain.
  @param  Signature                    The buffer to store the certificate chain hash.

  @retval TRUE  certificate chain hash is generated.
  @retval FALSE certificate chain hash is not generated.
**/
BOOLEAN
SpdmGenerateCertChainHash (
  IN     SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN     UINTN                        SlotIndex,
     OUT UINT8                        *Hash
  )
{
  ASSERT (SlotIndex < SpdmContext->LocalContext.SlotCount);
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.CertificateChain[SlotIndex], SpdmContext->LocalContext.CertificateChainSize[SlotIndex], Hash);
  return TRUE;
}

/**
  This function verifies the digest.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Digest                       The digest data buffer.
  @param  DigestSize                   Size in bytes of the digest data buffer.

  @retval TRUE  digest verification pass.
  @retval FALSE digest verification fail.
**/
BOOLEAN
SpdmVerifyDigest (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  IN UINTN                        DigestSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;

  CertBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;
  if ((CertBuffer != NULL) && (CertBufferSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);

    if (CompareMem (Digest, CertBufferHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyDigest - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! VerifyDigest - PASS !!!\n"));

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
SpdmVerifyCertificateChain (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChain,
  IN UINTN                        CertificateChainSize
  )
{
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  UINTN                                     HashSize;
  UINT8                                     *RootCertHash;
  UINTN                                     RootCertHashSize;
  BOOLEAN                                   Result;

  Result = SpdmVerifyCertificateChainData (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertificateChain, CertificateChainSize);
  if (!Result) {
    return FALSE;
  }

  RootCertHash = SpdmContext->LocalContext.PeerRootCertHashProvision;
  RootCertHashSize = SpdmContext->LocalContext.PeerRootCertHashProvisionSize;
  CertBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
  CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;

  if ((RootCertHash != NULL) && (RootCertHashSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    if (RootCertHashSize != HashSize) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (hash size mismatch) !!!\n"));
      return FALSE;
    }
    if (CompareMem ((UINT8 *)CertificateChain + sizeof(SPDM_CERT_CHAIN), RootCertHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (root hash mismatch) !!!\n"));
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

/**
  This function generates the challenge signature based upon M1M2 for authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Indicate of the signature generation for a requester or a responder.
  @param  ResponseMessage              The response message buffer.
  @param  ResponseMessageSize          Size in bytes of the response message buffer.
  @param  Signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
BOOLEAN
SpdmGenerateChallengeAuthSignature (
  IN     SPDM_DEVICE_CONTEXT        *SpdmContext,
  IN     BOOLEAN                    IsRequester,
  IN     VOID                       *ResponseMessage,
  IN     UINTN                      ResponseMessageSize,
     OUT UINT8                      *Signature
  )
{
  UINT8                         HashData[MAX_HASH_SIZE];
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT32                        HashSize;
  RETURN_STATUS                 Status;

  SignatureSize = GetSpdmAsymSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (IsRequester) {
    Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, ResponseMessage, ResponseMessageSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    Result = SpdmCalculateM1M2Hash (SpdmContext, IsRequester, HashData);
    if (!Result) {
      return FALSE;
    }

    Result = SpdmRequesterDataSignFunc (
              SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
              HashData,
              HashSize,
              Signature,
              &SignatureSize
              );
  } else {
    Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageC, ResponseMessage, ResponseMessageSize);
    if (RETURN_ERROR(Status)) {
      return FALSE;
    }

    Result = SpdmCalculateM1M2Hash (SpdmContext, IsRequester, HashData);
    if (!Result) {
      return FALSE;
    }

    Result = SpdmResponderDataSignFunc (
              SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
              HashData,
              HashSize,
              Signature,
              &SignatureSize
              );
  }

  return Result;
}

/**
  This function verifies the certificate chain hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertificateChainHash         The certificate chain hash data buffer.
  @param  CertificateChainHashSize     Size in bytes of the certificate chain hash data buffer.

  @retval TRUE  hash verification pass.
  @retval FALSE hash verification fail.
**/
BOOLEAN
SpdmVerifyCertificateChainHash (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChainHash,
  IN UINTN                        CertificateChainHashSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertBuffer = SpdmContext->ConnectionInfo.PeerCertChainBuffer;
    CertBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize;
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
    CertBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;
  } else {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);

  if (HashSize != CertificateChainHashSize) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainHash - FAIL !!!\n"));
    return FALSE;
  }
  if (CompareMem (CertificateChainHash, CertBufferHash, CertificateChainHashSize) != 0) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainHash - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainHash - PASS !!!\n"));
  return TRUE;
}

/**
  This function verifies the challenge signature based upon M1M2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Indicate of the signature verification for a requester or a responder.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyChallengeAuthSignature (
  IN  SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN  BOOLEAN                      IsRequester,
  IN  VOID                         *SignData,
  IN  UINTN                        SignDataSize
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

  Result = SpdmCalculateM1M2Hash (SpdmContext, !IsRequester, HashData);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainBuffer, CertChainBufferSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  if (IsRequester) {
    Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, CertBuffer, CertBufferSize, &Context);
    if (!Result) {
      return FALSE;
    }

    Result = SpdmAsymVerify (
              SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
              Context,
              HashData,
              HashSize,
              SignData,
              SignDataSize
              );
    SpdmAsymFree (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, Context);
  } else {
    Result = SpdmReqAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg, CertBuffer, CertBufferSize, &Context);
    if (!Result) {
      return FALSE;
    }

    Result = SpdmReqAsymVerify (
              SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
              Context,
              HashData,
              HashSize,
              SignData,
              SignDataSize
              );
    SpdmReqAsymFree (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg, Context);
  }

  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyChallengeSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyChallengeSignature - PASS !!!\n"));

  return TRUE;
}

/**
  This function calculate the measurement summary hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.
  @param  MeasurementSummaryHash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated.
  @retval FALSE measurement summary hash is not generated.
**/
BOOLEAN
SpdmGenerateMeasurementSummaryHash (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MeasurementSummaryHashType,
     OUT UINT8                *MeasurementSummaryHash
  )
{
  UINT8                         MeasurementData[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  UINTN                         Index;
  SPDM_MEASUREMENT_BLOCK_DMTF   *CachedMeasurmentBlock;
  UINTN                         MeasurmentDataSize;
  UINTN                         MeasurmentBlockSize;
  UINT8                         DeviceMeasurement[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  UINT8                         DeviceMeasurementCount;
  UINTN                         DeviceMeasurementSize;
  BOOLEAN                       Ret;

  switch (MeasurementSummaryHashType) {
  case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
    ZeroMem (MeasurementSummaryHash, GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
    break;

  case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
  case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:

    DeviceMeasurementSize = sizeof(DeviceMeasurement);
    Ret = SpdmMeasurementCollectionFunc (
            SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec,
            SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo,
            &DeviceMeasurementCount,
            DeviceMeasurement,
            &DeviceMeasurementSize
            );
    if (!Ret) {
      return Ret;
    }

    ASSERT(DeviceMeasurementCount <= MAX_SPDM_MEASUREMENT_BLOCK_COUNT);

    MeasurmentDataSize = 0;
    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      ASSERT (CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize == sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize);
      MeasurmentDataSize += CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }

    ASSERT (MeasurmentDataSize <= MAX_SPDM_MEASUREMENT_RECORD_SIZE);

    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    MeasurmentDataSize = 0;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      if ((MeasurementSummaryHashType == SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH) ||
          ((CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType & SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) == SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM)) {
        CopyMem (&MeasurementData[MeasurmentDataSize], &CachedMeasurmentBlock->MeasurementBlockDmtfHeader, CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize);
      }
      MeasurmentDataSize += CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, MeasurementData, MeasurmentDataSize, MeasurementSummaryHash);
    break;
  default:
    return FALSE;
    break;
  }
  return TRUE;
}

/**
  This function creates the measurement signature to response message based upon L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ResponseMessage              The measurement response message with empty signature to be filled.
  @param  ResponseMessageSize          Total size in bytes of the response message including signature.

  @retval TRUE  measurement signature is created.
  @retval FALSE measurement signature is not created.
**/
BOOLEAN
SpdmGenerateMeasurementSignature (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
  IN OUT VOID                   *ResponseMessage,
  IN     UINTN                  ResponseMessageSize
  )
{
  UINT8                         *Ptr;
  UINTN                         MeasurmentSigSize;
  UINTN                         SignatureSize;
  BOOLEAN                       Result;
  UINT8                         HashData[MAX_HASH_SIZE];
  UINT32                        HashSize;
  RETURN_STATUS                 Status;

  SignatureSize = GetSpdmAsymSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  MeasurmentSigSize = SPDM_NONCE_SIZE +
                      sizeof(UINT16) +
                      SpdmContext->LocalContext.OpaqueMeasurementRspSize +
                      SignatureSize;
  ASSERT (ResponseMessageSize > MeasurmentSigSize);
  Ptr = (VOID *)((UINT8 *)ResponseMessage + ResponseMessageSize - MeasurmentSigSize);
  
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, Ptr);
  Ptr += SPDM_NONCE_SIZE;

  *(UINT16 *)Ptr = (UINT16)SpdmContext->LocalContext.OpaqueMeasurementRspSize;
  Ptr += sizeof(UINT16);
  CopyMem (Ptr, SpdmContext->LocalContext.OpaqueMeasurementRsp, SpdmContext->LocalContext.OpaqueMeasurementRspSize);
  Ptr += SpdmContext->LocalContext.OpaqueMeasurementRspSize;

  Status = AppendManagedBuffer (&SpdmContext->Transcript.MessageM, ResponseMessage, ResponseMessageSize - SignatureSize);
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }

  Result = SpdmCalculateL1L2Hash (SpdmContext, HashData);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
  Result = SpdmResponderDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             HashData,
             HashSize,
             Ptr,
             &SignatureSize
             );
  return Result;
}

/**
  This function verifies the measurement signature based upon L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SignData                     The signature data buffer.
  @param  SignDataSize                 Size in bytes of the signature data buffer.

  @retval TRUE  signature verification pass.
  @retval FALSE signature verification fail.
**/
BOOLEAN
SpdmVerifyMeasurementSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  IN UINTN                        SignDataSize
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

  Result = SpdmCalculateL1L2Hash (SpdmContext, HashData);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    CertChainBuffer = (UINT8 *)SpdmContext->LocalContext.PeerCertChainProvision + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  } else {
    return FALSE;
  }

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainBuffer, CertChainBufferSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  SpdmAsymFree (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyMeasurementSignature - FAIL !!!\n"));
    return FALSE;
  }

  DEBUG((DEBUG_INFO, "!!! VerifyMeasurementSignature - PASS !!!\n"));
  return TRUE;
}

