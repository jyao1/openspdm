/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

SPDM_SESSION_INFO *
SpdmGetSessionInfoViaSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;

  SessionInfo = &SpdmContext->SessionInfo;
  if (SessionId != SessionInfo->SessionId) {
    ASSERT (FALSE);
    return NULL;
  }

  return SessionInfo;
}

SPDM_SESSION_INFO *
SpdmAssignSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     UINT8                     SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;

  SessionInfo = &SpdmContext->SessionInfo;
  if (SessionId == SessionInfo->SessionId) {
    ASSERT (FALSE);
    return NULL;
  }
  SessionInfo->SessionId = SessionId;

  return SessionInfo;
}

SPDM_SESSION_INFO *
SpdmAllocateSessionId (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
     OUT UINT8                     *SessionId
  )
{
  SPDM_SESSION_INFO          *SessionInfo;

  SessionInfo = &SpdmContext->SessionInfo;
  *SessionId = 0xFF;
  if (0xFF == SessionInfo->SessionId) {
    ASSERT (FALSE);
    return NULL;
  }
  SessionInfo->SessionId = *SessionId;

  return SessionInfo;
}

BOOLEAN
NeedSessionInfoForData (
  IN     EDKII_SPDM_DATA_TYPE      DataType
  )
{
  switch (DataType) {
  case EdkiiSpdmDataDheSecret:
  case EdkiiSpdmDataHandshakeSecret:
  case EdkiiSpdmDataMasterSecret:
  case EdkiiSpdmDataRequestHandshakeSecret:
  case EdkiiSpdmDataResponseHandshakeSecret:
  case EdkiiSpdmDataRequestDataSecret:
  case EdkiiSpdmDataResponseDataSecret:
  case EdkiiSpdmDataRequestHandshakeEncryptionKey:
  case EdkiiSpdmDataRequestHandshakeSalt:
  case EdkiiSpdmDataResponseHandshakeEncryptionKey:
  case EdkiiSpdmDataResponseHandshakeSalt:
  case EdkiiSpdmDataRequestDataEncryptionKey:
  case EdkiiSpdmDataRequestDataSalt:
  case EdkiiSpdmDataResponseDataEncryptionKey:
  case EdkiiSpdmDataResponseDataSalt:
  case EdkiiSpdmDataRequestFinishedKey:
  case EdkiiSpdmDataResponseFinishedKey:
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
  IN     EDKII_SPDM_DATA_TYPE      DataType,
  IN     EDKII_SPDM_DATA_PARAMETER *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;
  UINT8                     SlotNum;

  SpdmContext = Context;

  switch (DataType) {
  case EdkiiSpdmDataCapabilityFlags:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Capability.Flags = *(UINT32 *)Data;
    break;
  case EdkiiSpdmDataCapabilityCTExponent:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Capability.CTExponent = *(UINT8 *)Data;
    break;
  case EdkiiSpdmDataMeasurementHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = *(UINT32 *)Data;
    break;
  case EdkiiSpdmDataBaseAsymAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = *(UINT32 *)Data;
    break;
  case EdkiiSpdmDataBaseHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.BaseHashAlgo = *(UINT32 *)Data;
    break;
  case EdkiiSpdmDataDHENamedGroup:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.DHENamedGroup = *(UINT16 *)Data;
    break;
  case EdkiiSpdmDataAEADCipherSuite:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.AEADCipherSuite = *(UINT16 *)Data;
    break;
  case EdkiiSpdmDataKeySchedule:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Algorithm.KeySchedule = *(UINT16 *)Data;
    break;
  case EdkiiSpdmPeerPublicCertChains:
    SpdmContext->LocalContext.SpdmCertChainVarBufferSize = DataSize;
    SpdmContext->LocalContext.SpdmCertChainVarBuffer = Data;
    break;
  case EdkiiSpdmSlotCount:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SlotNum = *(UINT8 *)Data;
    if (SlotNum > MAX_SPDM_SLOT_COUNT) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.SlotCount = SlotNum;
    break;
  case EdkiiSpdmPublicCertChains:
    SlotNum = Parameter->AdditionalData[0];
    if (SlotNum > SpdmContext->LocalContext.SlotCount) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.CertificateChainSize[SlotNum] = DataSize;
    SpdmContext->LocalContext.CertificateChain[SlotNum] = Data;
    break;
  case EdkiiSpdmPrivateCertificate:
    SpdmContext->LocalContext.PrivatePemSize = DataSize;
    SpdmContext->LocalContext.PrivatePem = Data;
    break;
  case EdkiiSpdmMeasurementRecord:
    SpdmContext->LocalContext.DeviceMeasurementCount = Parameter->AdditionalData[0];
    SpdmContext->LocalContext.DeviceMeasurement = Data;
    break;
  case EdkiiSpdmDataPsk:
    SpdmContext->LocalContext.PskSize = DataSize;
    SpdmContext->LocalContext.Psk = Data;
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
  IN     EDKII_SPDM_DATA_TYPE      DataType,
  IN     EDKII_SPDM_DATA_PARAMETER *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;
  UINTN                      TargetDataSize;
  VOID                       *TargetData;
  UINT8                      SessionId;
  SPDM_SESSION_INFO          *SessionInfo;

  SpdmContext = Context;

  if (NeedSessionInfoForData (DataType)) {    
    if (Parameter->Location != EdkiiSpdmDataLocationSession) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionId = Parameter->AdditionalData[0];
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, SessionId);
    if (SessionInfo == NULL) {
      return RETURN_INVALID_PARAMETER;
    }
  }

  switch (DataType) {
  case EdkiiSpdmDataCapabilityFlags:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->LocalContext.Capability.Flags;
    break;
  case EdkiiSpdmDataCapabilityCTExponent:
    TargetDataSize = sizeof(UINT8);
    TargetData = &SpdmContext->LocalContext.Capability.CTExponent;
    break;
  case EdkiiSpdmDataMeasurementHashAlgo:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo;
    break;
  case EdkiiSpdmDataDheSecret:
    TargetDataSize = SessionInfo->DheKeySize;
    TargetData = SessionInfo->DheSecret;
    break;
  case EdkiiSpdmDataHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->HandshakeSecret;
    break;
  case EdkiiSpdmDataMasterSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->MasterSecret;
    break;
  case EdkiiSpdmDataRequestHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->RequestHandshakeSecret;
    break;
  case EdkiiSpdmDataResponseHandshakeSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->ResponseHandshakeSecret;
    break;
  case EdkiiSpdmDataRequestDataSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->RequestDataSecret;
    break;
  case EdkiiSpdmDataResponseDataSecret:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->ResponseDataSecret;
    break;
  case EdkiiSpdmDataRequestHandshakeEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->RequestHandshakeEncryptionKey;
    break;
  case EdkiiSpdmDataRequestHandshakeSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->RequestHandshakeSalt;
    break;
  case EdkiiSpdmDataResponseHandshakeEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->ResponseHandshakeEncryptionKey;
    break;
  case EdkiiSpdmDataResponseHandshakeSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->ResponseHandshakeSalt;
    break;
  case EdkiiSpdmDataRequestDataEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->RequestDataEncryptionKey;
    break;
  case EdkiiSpdmDataRequestDataSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->RequestDataSalt;
    break;
  case EdkiiSpdmDataResponseDataEncryptionKey:
    TargetDataSize = SessionInfo->AeadKeySize;
    TargetData = SessionInfo->ResponseDataEncryptionKey;
    break;
  case EdkiiSpdmDataResponseDataSalt:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->ResponseDataSalt;
    break;
  case EdkiiSpdmDataRequestFinishedKey:
    TargetDataSize = SessionInfo->HashSize;
    TargetData = SessionInfo->RequestFinishedKey;
    break;
  case EdkiiSpdmDataResponseFinishedKey:
    TargetDataSize = SessionInfo->AeadIvSize;
    TargetData = SessionInfo->ResponseFinishedKey;
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
SpdmInitContext (
  IN     VOID                      *Context
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  ZeroMem (SpdmContext, sizeof(SPDM_DEVICE_CONTEXT));
  SpdmContext->Version = SPDM_DEVICE_CONTEXT_VERSION;
  SpdmContext->Transcript.MessageA.MaxBufferSize  = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageB.MaxBufferSize  = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageC.MaxBufferSize  = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.M1M2.MaxBufferSize      = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.L1L2.MaxBufferSize      = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageK.MaxBufferSize  = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageF.MaxBufferSize  = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessagePK.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessagePF.MaxBufferSize = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;

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
