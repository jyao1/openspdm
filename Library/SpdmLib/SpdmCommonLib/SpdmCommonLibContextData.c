/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

VOID
SpdmSessionInfoInit (
  IN     SPDM_SESSION_INFO       *SessionInfo,
  IN     UINT32                  SessionId
  )
{
  ZeroMem (SessionInfo, sizeof(*SessionInfo));
  SessionInfo->SessionId = SessionId;
  SessionInfo->SessionTranscript.MessageK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SessionInfo->SessionTranscript.MessageF.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

SPDM_SESSION_INFO *
SpdmGetSessionInfoViaSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return NULL;
}

SPDM_SESSION_INFO *
SpdmAssignSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SessionInfo = SpdmContext->SessionInfo;

  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - Duplicated SessionId\n"));
      ASSERT(FALSE);
      return NULL;
    }
  }

  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == INVALID_SESSION_ID) {
      SpdmSessionInfoInit (&SessionInfo[Index], SessionId);
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return NULL;
}

UINT16
SpdmAllocateReqSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  )
{
  UINT16                     ReqSessionId;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if ((SessionInfo[Index].SessionId & 0xFFFF0000) == (INVALID_SESSION_ID & 0xFFFF0000)) {
      ReqSessionId = (UINT16)(0xFFFF - Index);
      return ReqSessionId;
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAllocateReqSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return (INVALID_SESSION_ID & 0xFFFF0000) >> 16;
}

UINT16
SpdmAllocateRspSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext
  )
{
  UINT16                     RspSessionId;
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if ((SessionInfo[Index].SessionId & 0xFFFF) == (INVALID_SESSION_ID & 0xFFFF)) {
      RspSessionId = (UINT16)(0xFFFF - Index);
      return RspSessionId;
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAllocateRspSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return (INVALID_SESSION_ID & 0xFFFF);
}

SPDM_SESSION_INFO *
SpdmFreeSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT32                    SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;
  UINTN                      Index;

  if (SessionId == INVALID_SESSION_ID) {
    DEBUG ((DEBUG_ERROR, "SpdmFreeSessionId - Invalid SessionId\n"));
    ASSERT(FALSE);
    return NULL;
  }

  SessionInfo = SpdmContext->SessionInfo;
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    if (SessionInfo[Index].SessionId == SessionId) {
      SpdmSessionInfoInit (&SessionInfo[Index], INVALID_SESSION_ID);
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmFreeSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return NULL;
}

BOOLEAN
NeedSessionInfoForData (
  IN     SPDM_DATA_TYPE      DataType
  )
{
  switch (DataType) {
  case SpdmDataDheSecret:
  case SpdmDataHandshakeSecret:
  case SpdmDataMasterSecret:
  case SpdmDataRequestHandshakeSecret:
  case SpdmDataResponseHandshakeSecret:
  case SpdmDataRequestDataSecret:
  case SpdmDataResponseDataSecret:
  case SpdmDataRequestHandshakeEncryptionKey:
  case SpdmDataRequestHandshakeSalt:
  case SpdmDataResponseHandshakeEncryptionKey:
  case SpdmDataResponseHandshakeSalt:
  case SpdmDataRequestDataEncryptionKey:
  case SpdmDataRequestDataSalt:
  case SpdmDataResponseDataEncryptionKey:
  case SpdmDataResponseDataSalt:
  case SpdmDataRequestFinishedKey:
  case SpdmDataResponseFinishedKey:
    return TRUE;
  }
  return FALSE;
}

/**
  Set a SPDM Session Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED            The DataType cannot be set.
  @retval RETURN_NOT_READY                Current session is not started.
**/
RETURN_STATUS
EFIAPI
SpdmSetData (
  IN     VOID                      *Context,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;
  UINT8                     SlotNum;

  SpdmContext = Context;

  switch (DataType) {
  case SpdmDataCapabilityFlags:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Capability.Flags = *(UINT32 *)Data;
    break;
  case SpdmDataCapabilityCTExponent:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Capability.CTExponent = *(UINT8 *)Data;
    break;
  case SpdmDataMeasurementHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = *(UINT32 *)Data;
    break;
  case SpdmDataBaseAsymAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = *(UINT32 *)Data;
    break;
  case SpdmDataBaseHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.BaseHashAlgo = *(UINT32 *)Data;
    break;
  case SpdmDataDHENamedGroup:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.DHENamedGroup = *(UINT16 *)Data;
    break;
  case SpdmDataAEADCipherSuite:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.AEADCipherSuite = *(UINT16 *)Data;
    break;
  case SpdmDataReqBaseAsymAlg:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = *(UINT16 *)Data;
    break;
  case SpdmDataKeySchedule:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.KeySchedule = *(UINT16 *)Data;
    break;
  case SpdmDataPeerPublicRootCertHash:
    SpdmContext->LocalContext.PeerRootCertHashVarBufferSize = DataSize;
    SpdmContext->LocalContext.PeerRootCertHashVarBuffer = Data;
    break;
  case SpdmDataPeerPublicCertChains:
    SpdmContext->LocalContext.PeerCertChainVarBufferSize = DataSize;
    SpdmContext->LocalContext.PeerCertChainVarBuffer = Data;
    break;
  case SpdmDataSlotCount:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SlotNum = *(UINT8 *)Data;
    if (SlotNum > MAX_SPDM_SLOT_COUNT) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.SlotCount = SlotNum;
    break;
  case SpdmDataPublicCertChains:
    SlotNum = Parameter->AdditionalData[0];
    if (SlotNum >= SpdmContext->LocalContext.SlotCount) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.CertificateChainSize[SlotNum] = DataSize;
    SpdmContext->LocalContext.CertificateChain[SlotNum] = Data;
    break;
  case SpdmDataMeasurementRecord:
    SpdmContext->LocalContext.DeviceMeasurementCount = Parameter->AdditionalData[0];
    SpdmContext->LocalContext.DeviceMeasurement = Data;
    break;
  case SpdmDataMutAuthRequested:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.MutAuthRequested = *(UINT8 *)Data;
    break;
  case SpdmDataPsk:
    SpdmContext->LocalContext.PskSize = DataSize;
    SpdmContext->LocalContext.Psk = Data;
    break;
  case SpdmDataPskHint:
    if (DataSize > MAX_SPDM_PSK_HINT_LENGTH) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.PskHintSize = DataSize;
    SpdmContext->LocalContext.PskHint = Data;
    break;
  default:
    return RETURN_UNSUPPORTED;
    break;
  }

  return RETURN_SUCCESS;
}

/**
  Get a SPDM Session Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGetData (
  IN     VOID                      *Context,
  IN     SPDM_DATA_TYPE            DataType,
  IN     SPDM_DATA_PARAMETER       *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  UINTN                      TargetDataSize;
  VOID                       *TargetData;
  UINT32                     SessionId;
  SPDM_SESSION_INFO          *SessionInfo;

  SpdmContext = Context;

  if (NeedSessionInfoForData (DataType)) {
    if (Parameter->Location != SpdmDataLocationSession) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionId = *(UINT32 *)Parameter->AdditionalData;
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_INVALID_PARAMETER;
    }
  }

  switch (DataType) {
  case SpdmDataCapabilityFlags:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->LocalContext.Capability.Flags;
    break;
  case SpdmDataCapabilityCTExponent:
    TargetDataSize = sizeof(UINT8);
    TargetData = &SpdmContext->LocalContext.Capability.CTExponent;
    break;
  case SpdmDataMeasurementHashAlgo:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo;
    break;
  case SpdmDataDheSecret:
    TargetDataSize = SessionInfo->DheKeySize;
    TargetData = SessionInfo->HandshakeSecret.DheSecret;
    break;
  case SpdmDataHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.HandshakeSecret;
    break;
  case SpdmDataMasterSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.MasterSecret;
    break;
  case SpdmDataRequestHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.RequestHandshakeSecret;
    break;
  case SpdmDataResponseHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.ResponseHandshakeSecret;
    break;
  case SpdmDataRequestDataSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->ApplicationSecret.RequestDataSecret;
    break;
  case SpdmDataResponseDataSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->ApplicationSecret.ResponseDataSecret;
    break;
  case SpdmDataRequestHandshakeEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->HandshakeSecret.RequestHandshakeEncryptionKey;
    break;
  case SpdmDataRequestHandshakeSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->HandshakeSecret.RequestHandshakeSalt;
    break;
  case SpdmDataResponseHandshakeEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->HandshakeSecret.ResponseHandshakeEncryptionKey;
    break;
  case SpdmDataResponseHandshakeSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->HandshakeSecret.ResponseHandshakeSalt;
    break;
  case SpdmDataRequestDataEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->ApplicationSecret.RequestDataEncryptionKey;
    break;
  case SpdmDataRequestDataSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->ApplicationSecret.RequestDataSalt;
    break;
  case SpdmDataResponseDataEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->ApplicationSecret.ResponseDataEncryptionKey;
    break;
  case SpdmDataResponseDataSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->ApplicationSecret.ResponseDataSalt;
    break;
  case SpdmDataRequestFinishedKey:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.RequestFinishedKey;
    break;
  case SpdmDataResponseFinishedKey:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->HandshakeSecret.ResponseFinishedKey;
    break;
  default:
    return RETURN_UNSUPPORTED;
    break;
  }

  if (*DataSize < TargetDataSize) {
    *DataSize = TargetDataSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *DataSize = TargetDataSize;
  CopyMem (Data, TargetData, TargetDataSize);

  return RETURN_SUCCESS;
}

BOOLEAN
SpdmIsVersionSupported (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     Version
  )
{
  UINTN  Index;

  for (Index = 0; Index < MAX_SPDM_VERSION_COUNT; Index++) {
    if (Version == SpdmContext->ConnectionInfo.Version[Index]) {
      return TRUE;
    }
  }
  return FALSE;
}

RETURN_STATUS
EFIAPI
SpdmRegisterDataSignFunc (
  IN     VOID                      *Context,
  IN     SPDM_DATA_SIGN_FUNC       SpdmDataSignFunc
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmRegisterDeviceIoFunc (
  IN     VOID                              *Context,
  IN     SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage,
  IN     SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->SendMessage = SendMessage;
  SpdmContext->ReceiveMessage = ReceiveMessage;
  return RETURN_SUCCESS;
}

UINT32
EFIAPI
SpdmGetLastError (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  return SpdmContext->ErrorState;
}

RETURN_STATUS
EFIAPI
SpdmSetAlignment (
  IN     VOID                      *Context,
  IN     UINT32                    Alignment
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->Alignment = Alignment;
  return RETURN_SUCCESS;
}

UINT32
EFIAPI
SpdmGetAlignment (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  if (SpdmContext->Alignment == 0) {
    SpdmContext->Alignment = 1;
  }
  return SpdmContext->Alignment;
}

SPDM_SESSION_TYPE
EFIAPI
SpdmGetSessionType (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  switch (SpdmContext->ConnectionInfo.Capability.Flags &
          (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP)) {
  case 0:
    return SpdmSessionTypeNone;
  case (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP) :
    return SpdmSessionTypeEncMac;
  case SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP :
    return SpdmSessionTypeMacOnly;
  default:
    return SpdmSessionTypeMax;
  }
}

RETURN_STATUS
EFIAPI
SpdmInitContext (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  ZeroMem (SpdmContext, sizeof(SPDM_DEVICE_CONTEXT));
  SpdmContext->Version = SPDM_DEVICE_CONTEXT_VERSION;
  SpdmContext->Alignment = 1;
  SpdmContext->Transcript.MessageA.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageB.MaxBufferSize    = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageC.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutB.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutC.MaxBufferSize = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.M1M2.MaxBufferSize        = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.L1L2.MaxBufferSize        = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->RetryTimes                           = MAX_SPDM_REQUEST_RETRY_TIMES;
  SpdmContext->ResponseState                        = SpdmResponseStateNormal;
  SpdmContext->CurrentToken                         = 0;

  RandomSeed (NULL, 0);
  return RETURN_SUCCESS;
}

UINTN
EFIAPI
SpdmGetContextSize (
  VOID
  )
{
  return sizeof(SPDM_DEVICE_CONTEXT);
}
