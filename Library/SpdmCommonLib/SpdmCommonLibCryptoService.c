/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/**
  This function returns peer certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer including SPDM_CERT_CHAIN header is returned.
  @retval FALSE Peer certificate chain buffer including SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetPeerCertChainBuffer (
  IN     VOID                     *Context,
     OUT VOID                     **CertChainBuffer,
     OUT UINTN                    *CertChainBufferSize
  )
{
  SPDM_DEVICE_CONTEXT          *SpdmContext;

  SpdmContext = Context;
  if (SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize != 0) {
    *CertChainBuffer = SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer;
    *CertChainBufferSize = SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize;
    return TRUE;
  }
  if (SpdmContext->LocalContext.PeerCertChainProvisionSize != 0) {
    *CertChainBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
    *CertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;
    return TRUE;
  }
  return FALSE;
}

/**
  This function returns peer certificate chain data without SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.

  @retval TRUE  Peer certificate chain data without SPDM_CERT_CHAIN header is returned.
  @retval FALSE Peer certificate chain data without SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetPeerCertChainData (
  IN     VOID                     *Context,
     OUT VOID                     **CertChainData,
     OUT UINTN                    *CertChainDataSize
  )
{
  SPDM_DEVICE_CONTEXT          *SpdmContext;
  BOOLEAN                      Result;
  UINTN                        HashSize;

  SpdmContext = Context;

  Result = SpdmGetPeerCertChainBuffer (SpdmContext, CertChainData, CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  *CertChainData = (UINT8 *)*CertChainData + sizeof(SPDM_CERT_CHAIN) + HashSize;
  *CertChainDataSize = *CertChainDataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  return TRUE;
}

/**
  This function returns local used certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Local used certificate chain buffer including SPDM_CERT_CHAIN header is returned.
  @retval FALSE Local used certificate chain buffer including SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetLocalCertChainBuffer (
  IN     VOID                     *Context,
     OUT VOID                     **CertChainBuffer,
     OUT UINTN                    *CertChainBufferSize
  )
{
  SPDM_DEVICE_CONTEXT          *SpdmContext;

  SpdmContext = Context;
  if (SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize != 0) {
    *CertChainBuffer = SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer;
    *CertChainBufferSize = SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize;
    return TRUE;
  }
  return FALSE;
}

/**
  This function returns local used certificate chain data without SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainData                Certitiface chain data without SPDM_CERT_CHAIN header.
  @param  CertChainDataSize            Size in bytes of the certitiface chain data.

  @retval TRUE  Local used certificate chain data without SPDM_CERT_CHAIN header is returned.
  @retval FALSE Local used certificate chain data without SPDM_CERT_CHAIN header is not found.
**/
BOOLEAN
EFIAPI
SpdmGetLocalCertChainData (
  IN     VOID                     *Context,
     OUT VOID                     **CertChainData,
     OUT UINTN                    *CertChainDataSize
  )
{
  SPDM_DEVICE_CONTEXT          *SpdmContext;
  BOOLEAN                      Result;
  UINTN                        HashSize;
  
  SpdmContext = Context;

  Result = SpdmGetLocalCertChainBuffer (SpdmContext, CertChainData, CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  *CertChainData = (UINT8 *)*CertChainData + sizeof(SPDM_CERT_CHAIN) + HashSize;
  *CertChainDataSize = *CertChainDataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  return TRUE;
}

/*
  This function calculates M1M2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsMut                        Indicate if this is from mutual authentication.
  @param  M1M2BufferSize               Size in bytes of the M1M2
  @param  M1M2Buffer                   The buffer to store the M1M2

  @retval RETURN_SUCCESS  M1M2 is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateM1M2 (
  IN     VOID                   *Context,
  IN     BOOLEAN                IsMut,
  IN OUT UINTN                  *M1M2BufferSize,
     OUT VOID                   *M1M2Buffer
  )
{
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  RETURN_STATUS                 Status;
  UINT32                        HashSize;
  UINT8                         HashData[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER          M1M2;

  SpdmContext = Context;

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

    // debug only
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

    // debug only
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&M1M2), GetManagedBufferSize(&M1M2), HashData);
    DEBUG((DEBUG_INFO, "M1M2 Hash - "));
    InternalDumpData (HashData, HashSize);
    DEBUG((DEBUG_INFO, "\n"));
  }

  *M1M2BufferSize = GetManagedBufferSize(&M1M2);
  CopyMem (M1M2Buffer, GetManagedBuffer(&M1M2), *M1M2BufferSize);

  return TRUE;
}

/*
  This function calculates L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  L1L2BufferSize               Size in bytes of the L1L2
  @param  L1L2Buffer                   The buffer to store the L1L2

  @retval RETURN_SUCCESS  L1L2 is calculated.
*/
BOOLEAN
EFIAPI
SpdmCalculateL1L2 (
  IN     VOID                   *Context,
  IN OUT UINTN                  *L1L2BufferSize,
     OUT VOID                   *L1L2Buffer
  )
{
  SPDM_DEVICE_CONTEXT           *SpdmContext;
  UINT32                        HashSize;
  UINT8                         HashData[MAX_HASH_SIZE];

  SpdmContext = Context;

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  DEBUG((DEBUG_INFO, "MessageM Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageM), GetManagedBufferSize(&SpdmContext->Transcript.MessageM));

  // debug only
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, GetManagedBuffer(&SpdmContext->Transcript.MessageM), GetManagedBufferSize(&SpdmContext->Transcript.MessageM), HashData);
  DEBUG((DEBUG_INFO, "L1L2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  *L1L2BufferSize = GetManagedBufferSize(&SpdmContext->Transcript.MessageM);
  CopyMem (L1L2Buffer, GetManagedBuffer(&SpdmContext->Transcript.MessageM), *L1L2BufferSize);

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
  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, SpdmContext->LocalContext.LocalCertChainProvision[SlotIndex], SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotIndex], Hash);
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
SpdmVerifyPeerDigests (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *Digest,
  IN UINTN                        DigestSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     CertChainBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;

  CertChainBuffer = SpdmContext->LocalContext.PeerCertChainProvision;
  CertChainBufferSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;
  if ((CertChainBuffer != NULL) && (CertChainBufferSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertChainBuffer, CertChainBufferSize, CertChainBufferHash);

    if (CompareMem (Digest, CertChainBufferHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyPeerDigests - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! VerifyPeerDigests - PASS !!!\n"));

  return TRUE;
}

/**
  This function verifies peer certificate chain buffer including SPDM_CERT_CHAIN header.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  CertChainBuffer              Certitiface chain buffer including SPDM_CERT_CHAIN header.
  @param  CertChainBufferSize          Size in bytes of the certitiface chain buffer.

  @retval TRUE  Peer certificate chain buffer verification passed.
  @retval FALSE Peer certificate chain buffer verification failed.
**/
BOOLEAN
SpdmVerifyPeerCertChainBuffer (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertChainBuffer,
  IN UINTN                        CertChainBufferSize
  )
{
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINTN                                     HashSize;
  UINT8                                     *RootCertHash;
  UINTN                                     RootCertHashSize;
  BOOLEAN                                   Result;

  Result = SpdmVerifyCertificateChainBuffer (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertChainBuffer, CertChainBufferSize);
  if (!Result) {
    return FALSE;
  }

  RootCertHash = SpdmContext->LocalContext.PeerRootCertHashProvision;
  RootCertHashSize = SpdmContext->LocalContext.PeerRootCertHashProvisionSize;
  CertChainData = SpdmContext->LocalContext.PeerCertChainProvision;
  CertChainDataSize = SpdmContext->LocalContext.PeerCertChainProvisionSize;

  if ((RootCertHash != NULL) && (RootCertHashSize != 0)) {
    HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    if (RootCertHashSize != HashSize) {
      DEBUG((DEBUG_INFO, "!!! VerifyPeerCertChainBuffer - FAIL (hash size mismatch) !!!\n"));
      return FALSE;
    }
    if (CompareMem ((UINT8 *)CertChainBuffer + sizeof(SPDM_CERT_CHAIN), RootCertHash, HashSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyPeerCertChainBuffer - FAIL (root hash mismatch) !!!\n"));
      return FALSE;
    }
  } else if ((CertChainData != NULL) && (CertChainDataSize != 0)) {
    if (CertChainDataSize != CertChainBufferSize) {
      DEBUG((DEBUG_INFO, "!!! VerifyPeerCertChainBuffer - FAIL !!!\n"));
      return FALSE;
    }
    if (CompareMem (CertChainBuffer, CertChainData, CertChainBufferSize) != 0) {
      DEBUG((DEBUG_INFO, "!!! VerifyPeerCertChainBuffer - FAIL !!!\n"));
      return FALSE;
    }
  }

  DEBUG((DEBUG_INFO, "!!! VerifyPeerCertChainBuffer - PASS !!!\n"));

  return TRUE;
}

/**
  This function generates the challenge signature based upon M1M2 for authentication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Indicate of the signature generation for a requester or a responder.
  @param  Signature                    The buffer to store the challenge signature.

  @retval TRUE  challenge signature is generated.
  @retval FALSE challenge signature is not generated.
**/
BOOLEAN
SpdmGenerateChallengeAuthSignature (
  IN     SPDM_DEVICE_CONTEXT        *SpdmContext,
  IN     BOOLEAN                    IsRequester,
     OUT UINT8                      *Signature
  )
{
  BOOLEAN                       Result;
  UINTN                         SignatureSize;
  UINT8                         M1M2Buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         M1M2BufferSize;

  M1M2BufferSize = sizeof(M1M2Buffer);
  Result = SpdmCalculateM1M2 (SpdmContext, IsRequester, &M1M2BufferSize, &M1M2Buffer);
  if (!Result) {
    return FALSE;
  }

  if (IsRequester) {
    SignatureSize = GetSpdmReqAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg);
    Result = SpdmRequesterDataSignFunc (
              SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg,
              SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
              M1M2Buffer,
              M1M2BufferSize,
              Signature,
              &SignatureSize
              );
  } else {
    SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
    Result = SpdmResponderDataSignFunc (
              SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
              SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
              M1M2Buffer,
              M1M2BufferSize,
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
  UINT8                                     CertChainBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;
  BOOLEAN                                   Result;

  Result = SpdmGetPeerCertChainBuffer (SpdmContext, (VOID **)&CertChainBuffer, &CertChainBufferSize);
  if (!Result) {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);

  SpdmHashAll (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo, CertChainBuffer, CertChainBufferSize, CertChainBufferHash);

  if (HashSize != CertificateChainHashSize) {
    DEBUG((DEBUG_INFO, "!!! VerifyCertificateChainHash - FAIL !!!\n"));
    return FALSE;
  }
  if (CompareMem (CertificateChainHash, CertChainBufferHash, CertificateChainHashSize) != 0) {
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
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     M1M2Buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     M1M2BufferSize;

  M1M2BufferSize = sizeof(M1M2Buffer);
  Result = SpdmCalculateM1M2 (SpdmContext, !IsRequester, &M1M2BufferSize, &M1M2Buffer);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainData, CertChainDataSize, -1,  &CertBuffer, &CertBufferSize);
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
              SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
              Context,
              M1M2Buffer,
              M1M2BufferSize,
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
              SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
              Context,
              M1M2Buffer,
              M1M2BufferSize,
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
  This function calculate the measurement summary hash size.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.

  @return 0 measurement summary hash type is invalid, NO_MEAS hash type or no MEAS capabilities.
  @return measurement summary hash size according to type.
**/
UINT32
SpdmGetMeasurementSummaryHashSize (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     BOOLEAN              IsRequester,
  IN     UINT8                MeasurementSummaryHashType
  )
{
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, IsRequester, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    return 0;
  }

  switch (MeasurementSummaryHashType) {
  case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
    return 0;
    break;

  case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
  case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
    return GetSpdmHashSize (SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo);
    break;
  }

  return 0;
}

/**
  This function calculate the measurement summary hash.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  MeasurementSummaryHashType   The type of the measurement summary hash.
  @param  MeasurementSummaryHash       The buffer to store the measurement summary hash.

  @retval TRUE  measurement summary hash is generated or skipped.
  @retval FALSE measurement summary hash is not generated.
**/
BOOLEAN
SpdmGenerateMeasurementSummaryHash (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     BOOLEAN              IsRequester,
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

  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, IsRequester, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    return TRUE;
  }

  switch (MeasurementSummaryHashType) {
  case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
    break;

  case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
  case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
    // get all measurement data
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

    // double confirm that MeasurmentData internal size is correct
    MeasurmentDataSize = 0;
    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      ASSERT (CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize == sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize);
      MeasurmentDataSize += CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      CachedMeasurmentBlock = (VOID *)((UINTN)CachedMeasurmentBlock + MeasurmentBlockSize);
    }

    ASSERT (MeasurmentDataSize <= MAX_SPDM_MEASUREMENT_RECORD_SIZE);

    // get required data and hash them
    CachedMeasurmentBlock = (VOID *)DeviceMeasurement;
    MeasurmentDataSize = 0;
    for (Index = 0; Index < DeviceMeasurementCount; Index++) {
      MeasurmentBlockSize = sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + CachedMeasurmentBlock->MeasurementBlockCommonHeader.MeasurementSize;
      // filter unneeded data
      if (((MeasurementSummaryHashType == SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH) && 
           ((CachedMeasurmentBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType & SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK) < SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST)) ||
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
  This function generates the measurement signature to response message based upon L1L2.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Signature                    The buffer to store the Signature.

  @retval TRUE  measurement signature is generated.
  @retval FALSE measurement signature is not generated.
**/
BOOLEAN
SpdmGenerateMeasurementSignature (
  IN     SPDM_DEVICE_CONTEXT    *SpdmContext,
     OUT UINT8                  *Signature
  )
{
  UINTN                         SignatureSize;
  BOOLEAN                       Result;
  UINT8                         L1L2Buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                         L1L2BufferSize;

  L1L2BufferSize = sizeof(L1L2Buffer);
  Result = SpdmCalculateL1L2 (SpdmContext, &L1L2BufferSize, L1L2Buffer);
  if (!Result) {
    return FALSE;
  }

  SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
  Result = SpdmResponderDataSignFunc (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             L1L2Buffer,
             L1L2BufferSize,
             Signature,
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
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  UINT8                                     *CertChainData;
  UINTN                                     CertChainDataSize;
  UINT8                                     L1L2Buffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  UINTN                                     L1L2BufferSize;

  L1L2BufferSize = sizeof(L1L2Buffer);
  Result = SpdmCalculateL1L2 (SpdmContext, &L1L2BufferSize, L1L2Buffer);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmGetPeerCertChainData (SpdmContext, (VOID **)&CertChainData, &CertChainDataSize);
  if (!Result) {
    return FALSE;
  }

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainData, CertChainDataSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo,
             SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo,
             Context,
             L1L2Buffer,
             L1L2BufferSize,
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

