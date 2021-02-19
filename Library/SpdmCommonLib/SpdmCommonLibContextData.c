/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

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
  case SpdmDataSessionUsePsk:
  case SpdmDataSessionMutAuthRequested:
  case SpdmDataSessionEndSessionAttributes:
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
  case SpdmDataSpdmVersion:
    if (DataSize > sizeof(SPDM_VERSION_NUMBER) * MAX_SPDM_VERSION_COUNT) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Version.SpdmVersionCount = (UINT8)(DataSize / sizeof(SPDM_VERSION_NUMBER));
      CopyMem (
        SpdmContext->ConnectionInfo.Version.SpdmVersion,
        Data,
        SpdmContext->ConnectionInfo.Version.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER)
        );
    } else {
      SpdmContext->LocalContext.Version.SpdmVersionCount = (UINT8)(DataSize / sizeof(SPDM_VERSION_NUMBER));
      CopyMem (
        SpdmContext->LocalContext.Version.SpdmVersion,
        Data,
        SpdmContext->LocalContext.Version.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER)
        );
    }
    break;
  case SpdmDataSecuredMessageVersion:
    if (DataSize > sizeof(SPDM_VERSION_NUMBER) * MAX_SPDM_VERSION_COUNT) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.SecuredMessageVersion.SpdmVersionCount = (UINT8)(DataSize / sizeof(SPDM_VERSION_NUMBER));
      CopyMem (
        SpdmContext->ConnectionInfo.SecuredMessageVersion.SpdmVersion,
        Data,
        SpdmContext->ConnectionInfo.SecuredMessageVersion.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER)
        );
    } else {
      SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersionCount = (UINT8)(DataSize / sizeof(SPDM_VERSION_NUMBER));
      CopyMem (
        SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersion,
        Data,
        SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER)
        );
    }
    break;
  case SpdmDataCapabilityFlags:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Capability.Flags = *(UINT32 *)Data;
    } else {
      SpdmContext->LocalContext.Capability.Flags = *(UINT32 *)Data;
    }
    break;
  case SpdmDataCapabilityCTExponent:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.Capability.CTExponent = *(UINT8 *)Data;
    break;
  case SpdmDataMeasurementSpec:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = *(UINT8 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.MeasurementSpec = *(UINT8 *)Data;
    }
    break;
  case SpdmDataMeasurementHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = *(UINT32 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.MeasurementHashAlgo = *(UINT32 *)Data;
    }
    break;
  case SpdmDataBaseAsymAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = *(UINT32 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.BaseAsymAlgo = *(UINT32 *)Data;
    }
    break;
  case SpdmDataBaseHashAlgo:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = *(UINT32 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.BaseHashAlgo = *(UINT32 *)Data;
    }
    break;
  case SpdmDataDHENamedGroup:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = *(UINT16 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.DHENamedGroup = *(UINT16 *)Data;
    }
    break;
  case SpdmDataAEADCipherSuite:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = *(UINT16 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.AEADCipherSuite = *(UINT16 *)Data;
    }
    break;
  case SpdmDataReqBaseAsymAlg:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = *(UINT16 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.ReqBaseAsymAlg = *(UINT16 *)Data;
    }
    break;
  case SpdmDataKeySchedule:
    if (DataSize != sizeof(UINT16)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (Parameter->Location == SpdmDataLocationConnection) {
      SpdmContext->ConnectionInfo.Algorithm.KeySchedule = *(UINT16 *)Data;
    } else {
      SpdmContext->LocalContext.Algorithm.KeySchedule = *(UINT16 *)Data;
    }
    break;
  case SpdmDataConnectionState:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->ConnectionInfo.ConnectionState = *(UINT32 *)Data;
    break;
  case SpdmDataResponseState:
    if (DataSize != sizeof(UINT32)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->ResponseState = *(UINT32 *)Data;
    break;
  case SpdmDataPeerPublicRootCertHash:
    SpdmContext->LocalContext.PeerRootCertHashProvisionSize = DataSize;
    SpdmContext->LocalContext.PeerRootCertHashProvision = Data;
    break;
  case SpdmDataPeerPublicCertChains:
    SpdmContext->LocalContext.PeerCertChainProvisionSize = DataSize;
    SpdmContext->LocalContext.PeerCertChainProvision = Data;
    break;
  case SpdmDataLocalSlotCount:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SlotNum = *(UINT8 *)Data;
    if (SlotNum > MAX_SPDM_SLOT_COUNT) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.SlotCount = SlotNum;
    break;
  case SpdmDataLocalPublicCertChain:
    SlotNum = Parameter->AdditionalData[0];
    if (SlotNum >= SpdmContext->LocalContext.SlotCount) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.LocalCertChainProvisionSize[SlotNum] = DataSize;
    SpdmContext->LocalContext.LocalCertChainProvision[SlotNum] = Data;
    break;
  case SpdmDataLocalUsedCertChainBuffer:
    if (DataSize > MAX_SPDM_CERT_CHAIN_SIZE) {
      return RETURN_OUT_OF_RESOURCES;
    }
    SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize;
    SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data;
    break;
  case SpdmDataPeerUsedCertChainBuffer:
    if (DataSize > MAX_SPDM_CERT_CHAIN_SIZE) {
      return RETURN_OUT_OF_RESOURCES;
    }
    SpdmContext->ConnectionInfo.PeerUsedCertChainBufferSize = DataSize;
    CopyMem (SpdmContext->ConnectionInfo.PeerUsedCertChainBuffer, Data, DataSize);
    break;
  case SpdmDataBasicMutAuthRequested:
    if (DataSize != sizeof(BOOLEAN)) {
      return RETURN_INVALID_PARAMETER;
    }
    MutAuthRequested = *(UINT8 *)Data;
    if (((MutAuthRequested != 0) &&
         (MutAuthRequested != 1)) ) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.BasicMutAuthRequested = MutAuthRequested;
    SpdmContext->EncapContext.ErrorState = 0;
    SpdmContext->EncapContext.RequestId = 0;
    SpdmContext->EncapContext.ReqSlotNum = Parameter->AdditionalData[0];
    break;
  case SpdmDataMutAuthRequested:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    MutAuthRequested = *(UINT8 *)Data;
    if (((MutAuthRequested != 0) &&
         (MutAuthRequested != SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED) &&
         (MutAuthRequested != SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST) &&
         (MutAuthRequested != SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS)) ) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.MutAuthRequested = MutAuthRequested;
    SpdmContext->EncapContext.ErrorState = 0;
    SpdmContext->EncapContext.RequestId = 0;
    SpdmContext->EncapContext.ReqSlotNum = Parameter->AdditionalData[0];
    break;
  case SpdmDataPskHint:
    if (DataSize > MAX_SPDM_PSK_HINT_LENGTH) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.PskHintSize = DataSize;
    SpdmContext->LocalContext.PskHint = Data;
    break;
  case SpdmDataSessionUsePsk:
    if (DataSize != sizeof(BOOLEAN)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->UsePsk = *(BOOLEAN *)Data;
    break;
  case SpdmDataSessionMutAuthRequested:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->MutAuthRequested = *(UINT8 *)Data;
    break;
  case SpdmDataSessionEndSessionAttributes:
    if (DataSize != sizeof(UINT8)) {
      return RETURN_INVALID_PARAMETER;
    }
    SessionInfo->EndSessionAttributes = *(UINT8 *)Data;
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
  case SpdmDataSpdmVersion:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = SpdmContext->ConnectionInfo.Version.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER);
    TargetData = SpdmContext->ConnectionInfo.Version.SpdmVersion;
    break;
  case SpdmDataSecuredMessageVersion:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = SpdmContext->ConnectionInfo.SecuredMessageVersion.SpdmVersionCount * sizeof(SPDM_VERSION_NUMBER);
    TargetData = SpdmContext->ConnectionInfo.SecuredMessageVersion.SpdmVersion;
    break;
  case SpdmDataCapabilityFlags:
    TargetDataSize = sizeof(UINT32);
    if (Parameter->Location == SpdmDataLocationConnection) {
      TargetData = &SpdmContext->ConnectionInfo.Capability.Flags;
    } else {
      TargetData = &SpdmContext->LocalContext.Capability.Flags;
    }
    break;
  case SpdmDataCapabilityCTExponent:
    TargetDataSize = sizeof(UINT8);
    if (Parameter->Location == SpdmDataLocationConnection) {
      TargetData = &SpdmContext->ConnectionInfo.Capability.CTExponent;
    } else {
      TargetData = &SpdmContext->LocalContext.Capability.CTExponent;
    }
    break;
  case SpdmDataMeasurementSpec:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT8);
    TargetData = &SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec;
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
  case SpdmDataConnectionState:
    if (Parameter->Location != SpdmDataLocationConnection) {
      return RETURN_INVALID_PARAMETER;
    }
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ConnectionInfo.ConnectionState;
    break;
  case SpdmDataResponseState:
    TargetDataSize = sizeof(UINT32);
    TargetData = &SpdmContext->ResponseState;
    break;
  case SpdmDataSessionUsePsk:
    TargetDataSize = sizeof(BOOLEAN);
    TargetData = &SessionInfo->UsePsk;
    break;
  case SpdmDataSessionMutAuthRequested:
    TargetDataSize = sizeof(UINT8);
    TargetData = &SessionInfo->MutAuthRequested;
    break;
  case SpdmDataSessionEndSessionAttributes:
    TargetDataSize = sizeof(UINT8);
    TargetData = &SessionInfo->EndSessionAttributes;
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
  Reset Message A cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageA (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
}

/**
  Reset Message B cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageB (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
}

/**
  Reset Message C cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageC (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
}

/**
  Reset Message MutB cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageMutB (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutB);
}

/**
  Reset Message MutC cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageMutC (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageMutC);
}

/**
  Reset Message M cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
**/
VOID
EFIAPI
SpdmResetMessageM (
  IN     VOID                                *Context
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
}

/**
  Append Message A cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageA (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Message, MessageSize);
}

/**
  Append Message B cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageB (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageB, Message, MessageSize);
}

/**
  Append Message C cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageC (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageC, Message, MessageSize);
}

/**
  Append Message MutB cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageMutB (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageMutB, Message, MessageSize);
}

/**
  Append Message MutC cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageMutC (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageMutC, Message, MessageSize);
}

/**
  Append Message M cache in SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageM (
  IN     VOID                                *Context,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_DEVICE_CONTEXT        *SpdmContext;

  SpdmContext = Context;
  return AppendManagedBuffer (&SpdmContext->Transcript.MessageM, Message, MessageSize);
}

/**
  Append Message K cache in SPDM context.

  @param  SpdmSessionInfo              A pointer to the SPDM session context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageK (
  IN     VOID                                *SessionInfo,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_SESSION_INFO       *SpdmSessionInfo;

  SpdmSessionInfo = SessionInfo;
  return AppendManagedBuffer (&SpdmSessionInfo->SessionTranscript.MessageK, Message, MessageSize);
}

/**
  Append Message F cache in SPDM context.

  @param  SpdmSessionInfo              A pointer to the SPDM session context.
  @param  Message                      Message buffer.
  @param  MessageSize                  Size in bytes of message buffer.

  @return RETURN_SUCCESS          Message is appended.
  @return RETURN_OUT_OF_RESOURCES Message is not appended because the internal cache is full.
**/
RETURN_STATUS
EFIAPI
SpdmAppendMessageF (
  IN     VOID                                *SessionInfo,
  IN     VOID                                *Message,
  IN     UINTN                               MessageSize
  )
{
  SPDM_SESSION_INFO       *SpdmSessionInfo;

  SpdmSessionInfo = SessionInfo;
  return AppendManagedBuffer (&SpdmSessionInfo->SessionTranscript.MessageF, Message, MessageSize);
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
  UINT8  MajorVersion;
  UINT8  MinorVersion;

  MajorVersion = ((Version >> 4) & 0xF);
  MinorVersion = (Version & 0xF);

  for (Index = 0; Index < SpdmContext->ConnectionInfo.Version.SpdmVersionCount; Index++) {
    if ((MajorVersion == SpdmContext->ConnectionInfo.Version.SpdmVersion[Index].MajorVersion) &&
        (MinorVersion == SpdmContext->ConnectionInfo.Version.SpdmVersion[Index].MinorVersion) ) {
      return TRUE;
    }
  }
  return FALSE;
}

/**
  This function returns if a capablities flag is supported in current SPDM connection.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  IsRequester                  Is the function called from a requester.
  @param  RequesterCapabilitiesFlag    The requester capabilities flag to be checked
  @param  ResponderCapabilitiesFlag    The responder capabilities flag to be checked

  @retval TRUE  the capablities flag is supported.
  @retval FALSE the capablities flag is not supported.
**/
BOOLEAN
SpdmIsCapabilitiesFlagSupported (
  IN     SPDM_DEVICE_CONTEXT       *SpdmContext,
  IN     BOOLEAN                   IsRequester, 
  IN     UINT32                    RequesterCapabilitiesFlag,
  IN     UINT32                    ResponderCapabilitiesFlag
  )
{
  UINT32  NegotiatedRequesterCapabilitiesFlag;
  UINT32  NegotiatedResponderCapabilitiesFlag;

  if (IsRequester) {
    NegotiatedRequesterCapabilitiesFlag = SpdmContext->LocalContext.Capability.Flags;
    NegotiatedResponderCapabilitiesFlag = SpdmContext->ConnectionInfo.Capability.Flags;
  } else {
    NegotiatedRequesterCapabilitiesFlag = SpdmContext->ConnectionInfo.Capability.Flags;
    NegotiatedResponderCapabilitiesFlag = SpdmContext->LocalContext.Capability.Flags;
  }

  if (((RequesterCapabilitiesFlag == 0) || ((NegotiatedRequesterCapabilitiesFlag & RequesterCapabilitiesFlag) != 0)) &&
      ((ResponderCapabilitiesFlag == 0) || ((NegotiatedResponderCapabilitiesFlag & ResponderCapabilitiesFlag) != 0)) ) {
    return TRUE;
  } else {
    return FALSE;
  }
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
  Get the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmGetLastSpdmErrorStruct (
  IN     VOID                      *Context,
     OUT SPDM_ERROR_STRUCT         *LastSpdmError
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  CopyMem (LastSpdmError, &SpdmContext->LastSpdmError, sizeof(SPDM_ERROR_STRUCT));
}

/**
  Set the last SPDM error struct of an SPDM context.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  LastSpdmError                Last SPDM error struct of an SPDM context.
*/
VOID
EFIAPI
SpdmSetLastSpdmErrorStruct (
  IN     VOID                      *Context,
  IN     SPDM_ERROR_STRUCT         *LastSpdmError
  )
{
  SPDM_DEVICE_CONTEXT       *SpdmContext;

  SpdmContext = Context;
  CopyMem (&SpdmContext->LastSpdmError, LastSpdmError, sizeof(SPDM_ERROR_STRUCT));
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
  VOID                      *SecuredMessageContext;
  UINTN                     SecuredMessageContextSize;
  UINTN                     Index;

  SpdmContext = Context;
  ZeroMem (SpdmContext, sizeof(SPDM_DEVICE_CONTEXT));
  SpdmContext->Version = SPDM_DEVICE_CONTEXT_VERSION;
  SpdmContext->Transcript.MessageA.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageB.MaxBufferSize    = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageC.MaxBufferSize    = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutB.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->Transcript.MessageMutC.MaxBufferSize = MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE;
  SpdmContext->Transcript.MessageM.MaxBufferSize    = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SpdmContext->RetryTimes                           = MAX_SPDM_REQUEST_RETRY_TIMES;
  SpdmContext->ResponseState                        = SpdmResponseStateNormal;
  SpdmContext->CurrentToken                         = 0;
  SpdmContext->LocalContext.Version.SpdmVersionCount                   = 2;
  SpdmContext->LocalContext.Version.SpdmVersion[0].MajorVersion        = 1;
  SpdmContext->LocalContext.Version.SpdmVersion[0].MinorVersion        = 0;
  SpdmContext->LocalContext.Version.SpdmVersion[0].Alpha               = 0;
  SpdmContext->LocalContext.Version.SpdmVersion[0].UpdateVersionNumber = 0;
  SpdmContext->LocalContext.Version.SpdmVersion[1].MajorVersion        = 1;
  SpdmContext->LocalContext.Version.SpdmVersion[1].MinorVersion        = 1;
  SpdmContext->LocalContext.Version.SpdmVersion[1].Alpha               = 0;
  SpdmContext->LocalContext.Version.SpdmVersion[1].UpdateVersionNumber = 0;
  SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersionCount                   = 1;
  SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersion[0].MajorVersion        = 1;
  SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersion[0].MinorVersion        = 1;
  SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersion[0].Alpha               = 0;
  SpdmContext->LocalContext.SecuredMessageVersion.SpdmVersion[0].UpdateVersionNumber = 0;
  SpdmContext->EncapContext.CertificateChainBuffer.MaxBufferSize = MAX_SPDM_MESSAGE_BUFFER_SIZE;

  SecuredMessageContext = (VOID *)((UINTN)(SpdmContext + 1));
  SecuredMessageContextSize = SpdmSecuredMessageGetContextSize();
  for (Index = 0; Index < MAX_SPDM_SESSION_COUNT; Index++) {
    SpdmContext->SessionInfo[Index].SecuredMessageContext = (VOID *)((UINTN)SecuredMessageContext + SecuredMessageContextSize * Index);
    SpdmSecuredMessageInitContext (SpdmContext->SessionInfo[Index].SecuredMessageContext);
  }

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
  return sizeof(SPDM_DEVICE_CONTEXT) + SpdmSecuredMessageGetContextSize() * MAX_SPDM_SESSION_COUNT;
}
