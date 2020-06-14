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
  UINT8                CertChainHash[MAX_HASH_SIZE];
  UINT8                Nonce[SPDM_NONCE_SIZE];
  UINT8                MeasurementSummaryHash[MAX_HASH_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
} SPDM_CHALLENGE_AUTH_RESPONSE_MAX;

#pragma pack()

BOOLEAN
SpdmRequesterVerifyCertificateChainHash (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *CertificateChainHash,
  UINTN                           CertificateChainHashSize
  )
{
  HASH_ALL                                  HashFunc;
  UINTN                                     HashSize;
  UINT8                                     CertBufferHash[MAX_HASH_SIZE];
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;

  CertBuffer = SpdmContext->LocalContext.SpdmCertChainVarBuffer;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize;
  if ((CertBuffer == NULL) || (CertBufferSize == 0)) {
    return FALSE;
  }
  
  HashFunc = GetSpdmHashFunc (SpdmContext);
  ASSERT(HashFunc != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);

  HashFunc (CertBuffer, CertBufferSize, CertBufferHash);
  
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

BOOLEAN
SpdmRequesterVerifyChallengeSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  UINTN                           SignDataSize
  )
{
  HASH_ALL                                  HashFunc;
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  ASYM_GET_PUBLIC_KEY_FROM_X509             GetPublicKeyFromX509Func;
  ASYM_FREE                                 FreeFunc;
  ASYM_VERIFY                               VerifyFunc;

  HashFunc = GetSpdmHashFunc (SpdmContext);
  ASSERT(HashFunc != NULL);
  HashSize = GetSpdmHashSize (SpdmContext);
  
  DEBUG((DEBUG_INFO, "MessageA Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));

  DEBUG((DEBUG_INFO, "MessageB Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));

  DEBUG((DEBUG_INFO, "MessageC Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));

  HashFunc (GetManagedBuffer(&SpdmContext->Transcript.M1M2), GetManagedBufferSize(&SpdmContext->Transcript.M1M2), HashData);
  DEBUG((DEBUG_INFO, "M1M2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  
  if ((SpdmContext->LocalContext.SpdmCertChainVarBuffer == NULL) || (SpdmContext->LocalContext.SpdmCertChainVarBufferSize == 0)) {
    return FALSE;
  }
  CertBuffer = (UINT8 *)SpdmContext->LocalContext.SpdmCertChainVarBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = SpdmContext->LocalContext.SpdmCertChainVarBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  GetPublicKeyFromX509Func = GetSpdmAsymGetPublicKeyFromX509 (SpdmContext);
  FreeFunc = GetSpdmAsymFree (SpdmContext);
  VerifyFunc = GetSpdmAsymVerify (SpdmContext);
  Result = GetPublicKeyFromX509Func (CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }
  
  Result = VerifyFunc (
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  FreeFunc (Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyChallengeSignature - FAIL !!!\n"));
    return FALSE;
  }
  DEBUG((DEBUG_INFO, "!!! VerifyChallengeSignature - PASS !!!\n"));
  
  return TRUE;
}

/*
  Authenticate based upon the key in one slot.
*/
RETURN_STATUS
EFIAPI
SpdmChallenge (
  IN     VOID                 *Context,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS                             Status;
  BOOLEAN                                   Result;
  SPDM_CHALLENGE_REQUEST                    SpdmRequest;
  SPDM_CHALLENGE_AUTH_RESPONSE_MAX          SpdmResponse;
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
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;
 
  SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  SpdmRequest.Header.RequestResponseCode = SPDM_CHALLENGE;
  SpdmRequest.Header.Param1 = SlotNum;
  SpdmRequest.Header.Param2 = MeasurementHashType;
  GetRandomNumber (SPDM_NONCE_SIZE, SpdmRequest.Nonce);
  DEBUG((DEBUG_INFO, "ClientNonce - "));
  InternalDumpData (SpdmRequest.Nonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));
  Status = SpdmSendRequest (SpdmContext, sizeof(SpdmRequest), &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageC, &SpdmRequest, sizeof(SpdmRequest));

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveResponse (SpdmContext, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CHALLENGE_AUTH_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_CHALLENGE_AUTH) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.Param1 != SlotNum) {
    return RETURN_DEVICE_ERROR;
  }
  HashSize = GetSpdmHashSize (SpdmContext);
  SignatureSize = GetSpdmAsymSize (SpdmContext);

  if (SpdmResponseSize <= sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) +
                          HashSize +
                          SPDM_NONCE_SIZE +
                          HashSize +
                          sizeof(UINT16)) {
    return RETURN_DEVICE_ERROR;
  }

  Ptr = SpdmResponse.CertChainHash;

  CertChainHash = Ptr;
  Ptr += HashSize;
  DEBUG((DEBUG_INFO, "CertChainHash (0x%x) - ", HashSize));
  InternalDumpData (CertChainHash, HashSize);
  DEBUG((DEBUG_INFO, "\n"));
  Result = SpdmRequesterVerifyCertificateChainHash (SpdmContext, CertChainHash, HashSize);
  if (!Result) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  ServerNonce = Ptr;
  DEBUG((DEBUG_INFO, "ServerNonce (0x%x) - ", SPDM_NONCE_SIZE));
  InternalDumpData (ServerNonce, SPDM_NONCE_SIZE);
  DEBUG((DEBUG_INFO, "\n"));
  Ptr += SPDM_NONCE_SIZE;

  MeasurementSummaryHash = Ptr;
  Ptr += HashSize;
  DEBUG((DEBUG_INFO, "MeasurementSummaryHash (0x%x) - ", HashSize));
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
  AppendManagedBuffer (&SpdmContext->Transcript.MessageC, &SpdmResponse, SpdmResponseSize - SignatureSize);
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageA), GetManagedBufferSize(&SpdmContext->Transcript.MessageA));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageB), GetManagedBufferSize(&SpdmContext->Transcript.MessageB));
  AppendManagedBuffer (&SpdmContext->Transcript.M1M2, GetManagedBuffer(&SpdmContext->Transcript.MessageC), GetManagedBufferSize(&SpdmContext->Transcript.MessageC));

  Opaque = Ptr;
  Ptr += OpaqueLength;
  DEBUG((DEBUG_INFO, "Opaque (0x%x):\n", OpaqueLength));
  InternalDumpHex (Opaque, OpaqueLength);

  Signature = Ptr;
  DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
  InternalDumpHex (Signature, SignatureSize);
  Result = SpdmRequesterVerifyChallengeSignature (SpdmContext, Signature, SignatureSize);
  if (!Result) {
    SpdmContext->ErrorState = SPDM_STATUS_ERROR_CERTIFIACTE_FAILURE;
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);

  if (MeasurementHash != NULL) {
    CopyMem (MeasurementHash, MeasurementSummaryHash, HashSize);
  }

  return RETURN_SUCCESS;
}
