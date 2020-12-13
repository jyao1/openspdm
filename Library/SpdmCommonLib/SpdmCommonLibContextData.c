/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/**
  This function initializes the session info.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.
**/
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

/**
  This function gets the session info via session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info.
**/
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

  DEBUG ((DEBUG_ERROR, "SpdmGetSessionInfoViaSessionId - not found SessionId\n"));
  return NULL;
}

/**
  This function assigns a new session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return session info associated with this new session ID.
**/
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
      SpdmContext->LatestSessionId = SessionId;
      return &SessionInfo[Index];
    }
  }

  DEBUG ((DEBUG_ERROR, "SpdmAssignSessionId - MAX SessionId\n"));
  ASSERT(FALSE);
  return NULL;
}

/**
  This function allocates half of session ID for a requester.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a requester.
**/
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

/**
  This function allocates half of session ID for a responder.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return half of session ID for a responder.
**/
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

/**
  This function frees a session ID.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SPDM session ID.

  @return freed session info assicated with this session ID.
**/
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

/**
  This function initializes the encapsulated context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  MutAuthRequested             Indicate of the MutAuthRequested through KEY_EXCHANGE or CHALLENG response.
  @param  SlotNum                      SlotNum to the peer in in CHALLENGE_AUTH request or RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER.
  @param  MeasurementHashType          MeasurementHashType to the peer in CHALLENGE_AUTH request.
**/
VOID
SpdmInitEncapEnv (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext,
  IN     UINT8                MutAuthRequested,
  IN     UINT8                SlotNum,
  IN     UINT8                MeasurementHashType
  )
{
  SpdmContext->EncapContext.ErrorState = 0;
  SpdmContext->EncapContext.SlotNum = SlotNum;
  SpdmContext->EncapContext.MeasurementHashType = MeasurementHashType;
}

/**
  Returns if an SPDM DataType is debug only.

  @param DataType  SPDM data type.

  @retval TRUE  This is debug only SPDM data type.
  @retval FALSE This is not debug only SPDM data type.
**/
BOOLEAN
IsDebugOnlyData (
  IN     SPDM_DATA_TYPE      DataType
  )
{
  if ((UINT32)DataType >= 0x80000000) {
    return TRUE;
  } else {
    return FALSE;
  }
}

/**
  Returns if an SPDM DataType requires session info.

  @param DataType  SPDM data type.

  @retval TRUE  session info is required.
  @retval FALSE session info is not required.
**/
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
  case SpdmDataRequestFinishedKey:
  case SpdmDataResponseFinishedKey:
    return TRUE;

  case SpdmDataSessionState:
  case SpdmDataExportMasterSecret:
  case SpdmDataRequestHandshakeEncryptionKey:
  case SpdmDataRequestHandshakeSalt:
  case SpdmDataResponseHandshakeEncryptionKey:
  case SpdmDataResponseHandshakeSalt:
  case SpdmDataRequestDataEncryptionKey:
  case SpdmDataRequestDataSalt:
  case SpdmDataResponseDataEncryptionKey:
  case SpdmDataResponseDataSalt:
  case SpdmDataRequestHandshakeSequenceNumber:
  case SpdmDataResponseHandshakeSequenceNumber:
  case SpdmDataRequestDataSequenceNumber:
  case SpdmDataResponseDataSequenceNumber:
    return TRUE;
  }
  return FALSE;
}

/**
  Set an SPDM context data.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataType                     Type of the SPDM context data.
  @param  Parameter                    Type specific parameter of the SPDM context data.
  @param  Data                         A pointer to the SPDM context data.
  @param  DataSize                     Size in bytes of the SPDM context data.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED           The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED         The DataType cannot be set.
  @retval RETURN_NOT_READY             Data is not ready to set.
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
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  UINT32                     SessionId;
  SPDM_SESSION_INFO          *SessionInfo;
  UINT8                      SlotNum;
  UINT8                      MutAuthRequested;

  if (IsDebugOnlyData (DataType)) {
    return RETURN_UNSUPPORTED;
  }

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
    SpdmContext->LocalContext.PeerRootCertHashProvisionSize = DataSize;
    SpdmContext->LocalContext.PeerRootCertHashProvision = Data;
    break;
  case SpdmDataPeerPublicCertChains:
    SpdmContext->LocalContext.PeerCertChainProvisionSize = DataSize;
    SpdmContext->LocalContext.PeerCertChainProvision = Data;
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
    MutAuthRequested = *(UINT8 *)Data;
    if (!((MutAuthRequested == 0) ||
          (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST)) ||
          (MutAuthRequested == (SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS))) ) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.MutAuthRequested = MutAuthRequested;
    SpdmInitEncapEnv (Context, MutAuthRequested, Parameter->AdditionalData[0], Parameter->AdditionalData[1]);
    break;
  case SpdmDataPskHint:
    if (DataSize > MAX_SPDM_PSK_HINT_LENGTH) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.PskHintSize = DataSize;
    SpdmContext->LocalContext.PskHint = Data;
    break;
  case SpdmDataRequestHandshakeSequenceNumber:
    if (DataSize != sizeof(SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber = *(UINT64 *)Data;
    break;
  case SpdmDataResponseHandshakeSequenceNumber:
    if (DataSize != sizeof(SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber = *(UINT64 *)Data;
    break;
  case SpdmDataRequestDataSequenceNumber:
    if (DataSize != sizeof(SessionInfo->ApplicationSecret.RequestDataSequenceNumber)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->ApplicationSecret.RequestDataSequenceNumber = *(UINT64 *)Data;
    break;
  case SpdmDataResponseDataSequenceNumber:
    if (DataSize != sizeof(SessionInfo->ApplicationSecret.ResponseDataSequenceNumber)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->ApplicationSecret.ResponseDataSequenceNumber = *(UINT64 *)Data;
    break;
  default:
    return RETURN_UNSUPPORTED;
    break;
  }

  return RETURN_SUCCESS;
}

/**
  Get an SPDM context data.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataType                     Type of the SPDM context data.
  @param  Parameter                    Type specific parameter of the SPDM context data.
  @param  Data                         A pointer to the SPDM context data.
  @param  DataSize                     Size in bytes of the SPDM context data.
                                       On input, it means the size in bytes of Data buffer.
                                       On output, it means the size in bytes of copied Data buffer if RETURN_SUCCESS,
                                       and means the size in bytes of desired Data buffer if RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS               The SPDM context data is set successfully.
  @retval RETURN_INVALID_PARAMETER     The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED           The DataType is unsupported.
  @retval RETURN_NOT_FOUND             The DataType cannot be found.
  @retval RETURN_NOT_READY             The Data is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
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
  SPDM_SESSION_TYPE          SessionType;

  if (IsDebugOnlyData (DataType)) {
    return RETURN_UNSUPPORTED;
  }

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
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ConnectionInfo.Capability.Flags;
    break;
  case SpdmDataCapabilityCTExponent:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT8);
    TargetData = &SpdmContext->ConnectionInfo.Capability.CTExponent;
    break;
  case SpdmDataMeasurementHashAlgo:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo;
    break;
  case SpdmDataBaseAsymAlgo:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo;
    break;
  case SpdmDataBaseHashAlgo:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo;
    break;
  case SpdmDataDHENamedGroup:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT16);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup;
    break;
  case SpdmDataAEADCipherSuite:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT16);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite;
    break;
  case SpdmDataReqBaseAsymAlg:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT16);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg;
    break;
  case SpdmDataKeySchedule:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT16);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.KeySchedule;
    break;

  case SpdmDataSessionType:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    switch (SpdmContext->ConnectionInfo.Capability.Flags &
            (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP)) {
    case 0:
      SessionType = SpdmSessionTypeNone;
      break;
    case (SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP) :
      SessionType = SpdmSessionTypeEncMac;
      break;
    case SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP :
      SessionType = SpdmSessionTypeMacOnly;
      break;
    default:
      ASSERT(FALSE);
      SessionType = SpdmSessionTypeMax;
      break;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SessionType;
    break;
  case SpdmDataSessionState:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SessionInfo->SessionState;
    break;
  case SpdmDataExportMasterSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret.ExportMasterSecret;
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
  case SpdmDataRequestHandshakeSequenceNumber:
    TargetDataSize = sizeof(SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber);
    TargetData = &SessionInfo->HandshakeSecret.RequestHandshakeSequenceNumber;
    break;
  case SpdmDataResponseHandshakeSequenceNumber:
    TargetDataSize = sizeof(SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber);
    TargetData = &SessionInfo->HandshakeSecret.ResponseHandshakeSequenceNumber;
    break;
  case SpdmDataRequestDataSequenceNumber:
    TargetDataSize = sizeof(SessionInfo->ApplicationSecret.RequestDataSequenceNumber);
    TargetData = &SessionInfo->ApplicationSecret.RequestDataSequenceNumber;
    break;
  case SpdmDataResponseDataSequenceNumber:
    TargetDataSize = sizeof(SessionInfo->ApplicationSecret.ResponseDataSequenceNumber);
    TargetData = &SessionInfo->ApplicationSecret.ResponseDataSequenceNumber;
    break;
  //
  // Debug Data only
  //
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

/**
  This function returns if a given version is supported based upon the GET_VERSION/VERSION.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Version                      The SPDM Version.

  @retval TRUE  the version is supported.
  @retval FALSE the version is not supported.
**/
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

/**
  Register SPDM data signing function.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SpdmDataSignFunc             The fuction to sign the SPDM data.
**/
VOID
EFIAPI
SpdmRegisterDataSignFunc (
  IN     VOID                      *Context,
  IN     SPDM_DATA_SIGN_FUNC       SpdmDataSignFunc
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->LocalContext.SpdmDataSignFunc = SpdmDataSignFunc;
  return ;
}

/**
  Register SPDM PSK HMAC function.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SpdmPskHmacFunc              The fuction to HMAC data with PSK.
**/
VOID
EFIAPI
SpdmRegisterPskHmacFunc (
  IN     VOID                      *Context,
  IN     SPDM_PSK_HMAC_FUNC        SpdmPskHmacFunc
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->LocalContext.SpdmPskHmacFunc = SpdmPskHmacFunc;
  return ;
}

/**
  Register SPDM device input/output functions.

  This function must be called after SpdmInitContext, and before any SPDM communication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SendMessage                  The fuction to send an SPDM transport layer message.
  @param  ReceiveMessage               The fuction to receive an SPDM transport layer message.
**/
VOID
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
  return ;
}

/**
  Register SPDM transport layer encode/decode functions for SPDM or APP messages.

  This function must be called after SpdmInitContext, and before any SPDM communication.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  TransportEncodeMessage       The fuction to encode an SPDM or APP message to a transport layer message.
  @param  TransportDecodeMessage       The fuction to decode an SPDM or APP message from a transport layer message.
**/
VOID
EFIAPI
SpdmRegisterTransportLayerFunc (
  IN     VOID                                *Context,
  IN     SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC  TransportEncodeMessage,
  IN     SPDM_TRANSPORT_DECODE_MESSAGE_FUNC  TransportDecodeMessage
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  SpdmContext->TransportEncodeMessage = TransportEncodeMessage;
  SpdmContext->TransportDecodeMessage = TransportDecodeMessage;
  return ;
}

/**
  Get the last error of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return Last error of an SPDM context.
*/
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

/**
  Initialize an SPDM context.

  The size in bytes of the SpdmContext can be returned by SpdmGetContextSize.

  @param  SpdmContext                  A pointer to the SPDM context.
*/
VOID
EFIAPI
SpdmInitContext (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  ZeroMem (SpdmContext, sizeof(SPDM_DEVICE_CONTEXT));
  SpdmContext->Version = SPDM_DEVICE_CONTEXT_VERSION;
  SpdmContext->Transcript.MessageA.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageB.MaxBufferSize    = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageC.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutB.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutC.MaxBufferSize = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.M1M2.MaxBufferSize        = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.L1L2.MaxBufferSize        = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->RetryTimes                           = MAX_SPDM_REQUEST_RETRY_TIMES;
  SpdmContext->ResponseState                        = SpdmResponseStateNormal;
  SpdmContext->CurrentToken                         = 0;
  SpdmContext->EncapContext.CertificateChainBuffer.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;

  RandomSeed (NULL, 0);
  return ;
}

/**
  Return the size in bytes of the SPDM context.

  @return the size in bytes of the SPDM context.
**/
UINTN
EFIAPI
SpdmGetContextSize (
  VOID
  )
{
  return sizeof(SPDM_DEVICE_CONTEXT);
}
