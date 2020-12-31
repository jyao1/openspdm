/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmSecuredMessageLibInternal.h"

UINTN
EFIAPI
SpdmSecuredMessageGetContextSize (
  VOID
  )
{
  return sizeof(SPDM_SECURED_MESSAGE_CONTEXT);
}

VOID
EFIAPI
SpdmSecuredMessageInitContext (
  IN     VOID                     *SpdmSecuredMessageContext
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  ZeroMem (SecuredMessageContext, sizeof(SPDM_SECURED_MESSAGE_CONTEXT));

  RandomSeed (NULL, 0);
}

VOID
EFIAPI
SpdmSecuredMessageSetUsePsk (
  IN VOID                         *SpdmSecuredMessageContext,
  IN BOOLEAN                      UsePsk
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  SecuredMessageContext->UsePsk = UsePsk;
}

VOID
EFIAPI
SpdmSecuredMessageSetSessionState (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_SESSION_STATE           SessionState
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  SecuredMessageContext->SessionState = SessionState;
}

SPDM_SESSION_STATE
EFIAPI
SpdmSecuredMessageGetSessionState (
  IN VOID                         *SpdmSecuredMessageContext
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  return SecuredMessageContext->SessionState;
}

VOID
EFIAPI
SpdmSecuredMessageSetSessionType (
  IN VOID                         *SpdmSecuredMessageContext,
  IN SPDM_SESSION_TYPE            SessionType
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  SecuredMessageContext->SessionType = SessionType;
}

VOID
EFIAPI
SpdmSecuredMessageSetAlgorithms (
  IN VOID                         *SpdmSecuredMessageContext,
  IN UINT32                       BaseHashAlgo,
  IN UINT16                       DHENamedGroup,
  IN UINT16                       AEADCipherSuite,
  IN UINT16                       KeySchedule
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  SecuredMessageContext->BaseHashAlgo = BaseHashAlgo;
  SecuredMessageContext->DHENamedGroup = DHENamedGroup;
  SecuredMessageContext->AEADCipherSuite = AEADCipherSuite;
  SecuredMessageContext->KeySchedule = KeySchedule;
  
  SecuredMessageContext->HashSize      = GetSpdmHashSize (SecuredMessageContext->BaseHashAlgo);
  SecuredMessageContext->DheKeySize    = GetSpdmDheKeySize (SecuredMessageContext->DHENamedGroup);
  SecuredMessageContext->AeadKeySize   = GetSpdmAeadKeySize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadIvSize    = GetSpdmAeadIvSize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadBlockSize = GetSpdmAeadBlockSize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadTagSize   = GetSpdmAeadTagSize (SecuredMessageContext->AEADCipherSuite);
}

VOID
EFIAPI
SpdmSecuredMessageSetPskHint (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *PskHint,
  IN UINTN                        PskHintSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  SecuredMessageContext->PskHint     = PskHint;
  SecuredMessageContext->PskHintSize = PskHintSize;
}

RETURN_STATUS
EFIAPI
SpdmSecuredMessageImportDheSecret (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *DheSecret,
  IN UINTN                        DheSecretSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  if (DheSecretSize > SecuredMessageContext->DheKeySize) {
    return RETURN_OUT_OF_RESOURCES;
  }
  SecuredMessageContext->DheKeySize = DheSecretSize;
  CopyMem (SecuredMessageContext->MasterSecret.DheSecret, DheSecret, DheSecretSize);
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmSecuredMessageExportMasterSecret (
  IN     VOID                         *SpdmSecuredMessageContext,
     OUT VOID                         *ExportMasterSecret,
  IN OUT UINTN                        *ExportMasterSecretSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  if (*ExportMasterSecretSize < SecuredMessageContext->HashSize) {
    *ExportMasterSecretSize = SecuredMessageContext->HashSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *ExportMasterSecretSize = SecuredMessageContext->HashSize;
  CopyMem (ExportMasterSecret, SecuredMessageContext->HandshakeSecret.ExportMasterSecret, SecuredMessageContext->HashSize);
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmSecuredMessageExportSessionKeys (
  IN     VOID                         *SpdmSecuredMessageContext,
     OUT VOID                         *SessionKeys,
  IN OUT UINTN                        *SessionKeysSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;
  UINTN                                  StructSize;
  SPDM_SECURE_SESSION_KEYS_STRUCT        *SessionkeysStruct;
  UINT8                                  *Ptr;

  SecuredMessageContext = SpdmSecuredMessageContext;
  StructSize = sizeof(SPDM_SECURE_SESSION_KEYS_STRUCT) + (SecuredMessageContext->AeadKeySize + SecuredMessageContext->AeadIvSize + sizeof(UINT64)) * 2;

  if (*SessionKeysSize < StructSize) {
    *SessionKeysSize = StructSize;
    return RETURN_BUFFER_TOO_SMALL;
  }

  SessionkeysStruct = SessionKeys;
  SessionkeysStruct->Version = SPDM_SECURE_SESSION_KEYS_STRUCT_VERSION;
  SessionkeysStruct->AeadKeySize = (UINT32)SecuredMessageContext->AeadKeySize;
  SessionkeysStruct->AeadIvSize = (UINT32)SecuredMessageContext->AeadIvSize;

  Ptr = (VOID *)(SessionkeysStruct + 1);
  CopyMem (Ptr, SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, SecuredMessageContext->AeadKeySize);
  Ptr += SecuredMessageContext->AeadKeySize;
  CopyMem (Ptr, SecuredMessageContext->ApplicationSecret.RequestDataSalt, SecuredMessageContext->AeadIvSize);
  Ptr += SecuredMessageContext->AeadIvSize;
  CopyMem (Ptr, &SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber, sizeof(UINT64));
  Ptr += sizeof(UINT64);
  CopyMem (Ptr, SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, SecuredMessageContext->AeadKeySize);
  Ptr += SecuredMessageContext->AeadKeySize;
  CopyMem (Ptr, SecuredMessageContext->ApplicationSecret.ResponseDataSalt, SecuredMessageContext->AeadIvSize);
  Ptr += SecuredMessageContext->AeadIvSize;
  CopyMem (Ptr, &SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber, sizeof(UINT64));
  Ptr += sizeof(UINT64);
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmSecuredMessageImportSessionKeys (
  IN     VOID                         *SpdmSecuredMessageContext,
  IN     VOID                         *SessionKeys,
  IN     UINTN                        SessionKeysSize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;
  UINTN                                  StructSize;
  SPDM_SECURE_SESSION_KEYS_STRUCT        *SessionkeysStruct;
  UINT8                                  *Ptr;

  SecuredMessageContext = SpdmSecuredMessageContext;
  StructSize = sizeof(SPDM_SECURE_SESSION_KEYS_STRUCT) + (SecuredMessageContext->AeadKeySize + SecuredMessageContext->AeadIvSize + sizeof(UINT64)) * 2;

  if (SessionKeysSize != StructSize) {
    return RETURN_INVALID_PARAMETER;
  }

  SessionkeysStruct = SessionKeys;
  if ((SessionkeysStruct->Version != SPDM_SECURE_SESSION_KEYS_STRUCT_VERSION) ||
      (SessionkeysStruct->AeadKeySize != SecuredMessageContext->AeadKeySize) ||
      (SessionkeysStruct->AeadIvSize != SecuredMessageContext->AeadIvSize) ) {
    return RETURN_INVALID_PARAMETER;
  }

  Ptr = (VOID *)(SessionkeysStruct + 1);
  CopyMem (SecuredMessageContext->ApplicationSecret.RequestDataEncryptionKey, Ptr, SecuredMessageContext->AeadKeySize);
  Ptr += SecuredMessageContext->AeadKeySize;
  CopyMem (SecuredMessageContext->ApplicationSecret.RequestDataSalt, Ptr, SecuredMessageContext->AeadIvSize);
  Ptr += SecuredMessageContext->AeadIvSize;
  CopyMem (&SecuredMessageContext->ApplicationSecret.RequestDataSequenceNumber, Ptr, sizeof(UINT64));
  Ptr += sizeof(UINT64);
  CopyMem (SecuredMessageContext->ApplicationSecret.ResponseDataEncryptionKey, Ptr, SecuredMessageContext->AeadKeySize);
  Ptr += SecuredMessageContext->AeadKeySize;
  CopyMem (SecuredMessageContext->ApplicationSecret.ResponseDataSalt, Ptr, SecuredMessageContext->AeadIvSize);
  Ptr += SecuredMessageContext->AeadIvSize;
  CopyMem (&SecuredMessageContext->ApplicationSecret.ResponseDataSequenceNumber, Ptr, sizeof(UINT64));
  Ptr += sizeof(UINT64);
  return RETURN_SUCCESS;
}

