/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmSecuredMessageLibInternal.h"

/**
  Return the size in bytes of the SPDM secured message context.

  @return the size in bytes of the SPDM secured message context.
**/
UINTN
EFIAPI
SpdmSecuredMessageGetContextSize (
  VOID
  )
{
  return sizeof(SPDM_SECURED_MESSAGE_CONTEXT);
}

/**
  Initialize an SPDM secured message context.

  The size in bytes of the SpdmSecuredMessageContext can be returned by SpdmSecuredMessageGetContextSize.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
*/
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

/**
  Set UsePsk to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  UsePsk                       Indicate if the SPDM session use PSK.
*/
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

/**
  Set SessionState to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  SessionState                 Indicate the SPDM session state.
*/
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

/**
  Return SessionState of an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.

  @return the SPDM session state.
*/
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

/**
  Set SessionType to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  SessionType                  Indicate the SPDM session type.
*/
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

/**
  Set Algorithm to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  BaseHashAlgo                 Indicate the negotiated BaseHashAlgo for the SPDM session.
  @param  DHENamedGroup                Indicate the negotiated DHENamedGroup for the SPDM session.
  @param  AEADCipherSuite              Indicate the negotiated AEADCipherSuite for the SPDM session.
  @param  KeySchedule                  Indicate the negotiated KeySchedule for the SPDM session.
*/
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
  SecuredMessageContext->DheKeySize    = GetSpdmDhePubKeySize (SecuredMessageContext->DHENamedGroup);
  SecuredMessageContext->AeadKeySize   = GetSpdmAeadKeySize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadIvSize    = GetSpdmAeadIvSize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadBlockSize = GetSpdmAeadBlockSize (SecuredMessageContext->AEADCipherSuite);
  SecuredMessageContext->AeadTagSize   = GetSpdmAeadTagSize (SecuredMessageContext->AEADCipherSuite);
}

/**
  Set the PskHint to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  PskHint                      Indicate the PSK hint.
  @param  PskHintSize                  The size in bytes of the PSK hint.
*/
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

/**
  Import the DHE Secret to an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  DheSecret                    Indicate the DHE secret.
  @param  DheSecretSize                The size in bytes of the DHE secret.

  @retval RETURN_SUCCESS  DHE Secret is imported.
*/
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

/**
  Export the ExportMasterSecret from an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  ExportMasterSecret           Indicate the buffer to store the ExportMasterSecret.
  @param  ExportMasterSecretSize       The size in bytes of the ExportMasterSecret.

  @retval RETURN_SUCCESS  ExportMasterSecret is exported.
*/
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

/**
  Export the SessionKeys from an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  SessionKeys                  Indicate the buffer to store the SessionKeys in SPDM_SECURE_SESSION_KEYS_STRUCT.
  @param  SessionKeysSize              The size in bytes of the SessionKeys in SPDM_SECURE_SESSION_KEYS_STRUCT.

  @retval RETURN_SUCCESS  SessionKeys are exported.
*/
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

/**
  Import the SessionKeys from an SPDM secured message context.

  @param  SpdmSecuredMessageContext    A pointer to the SPDM secured message context.
  @param  SessionKeys                  Indicate the buffer to store the SessionKeys in SPDM_SECURE_SESSION_KEYS_STRUCT.
  @param  SessionKeysSize              The size in bytes of the SessionKeys in SPDM_SECURE_SESSION_KEYS_STRUCT.

  @retval RETURN_SUCCESS  SessionKeys are imported.
*/
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

/**
  Get the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmSecuredMessageGetLastSpdmErrorStruct (
  IN     VOID                      *SpdmSecuredMessageContext,
     OUT SPDM_ERROR_STRUCT         *LastSpdmError
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  CopyMem (LastSpdmError, &SecuredMessageContext->LastSpdmError, sizeof(SPDM_ERROR_STRUCT));
}

/**
  Set the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmSecuredMessageSetLastSpdmErrorStruct (
  IN     VOID                      *SpdmSecuredMessageContext,
  IN     SPDM_ERROR_STRUCT         *LastSpdmError
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  CopyMem (&SecuredMessageContext->LastSpdmError, LastSpdmError, sizeof(SPDM_ERROR_STRUCT));
}
