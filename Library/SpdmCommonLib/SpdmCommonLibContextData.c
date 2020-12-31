/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

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
  SpdmContext->EncapContext.EncapState = 0;
  SpdmContext->EncapContext.RequestId = 0;
  SpdmContext->EncapContext.SlotNum = SlotNum;
  SpdmContext->EncapContext.MeasurementHashType = MeasurementHashType;
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
  case SpdmDataSessionUsePsk:
  case SpdmDataSessionMutAuthRequested:
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
  case SpdmDataLocalUsedCertChainBuffer:
    if (DataSize > MAX_SPDM_CERT_CHAIN_SIZE) {
      return RETURN_OUT_OF_RESOURCES;
    }
    SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize;
    SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data;
    break;
  case SpdmDataPeerCertChainBuffer:
    if (DataSize > MAX_SPDM_CERT_CHAIN_SIZE) {
      return RETURN_OUT_OF_RESOURCES;
    }
    SpdmContext->ConnectionInfo.PeerCertChainBufferSize = DataSize;
    CopyMem (SpdmContext->ConnectionInfo.PeerCertChainBuffer, Data, DataSize);
    break;
  case SpdmDataBasicMutAuthRequested:
    if (DataSize != sizeof(BOOLEAN)) {
      return RETURN_INVALID_PARAMETER;
    }
    SpdmContext->LocalContext.BasicMutAuthRequested = *(UINT8 *)Data;
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

  for (Index = 0; Index < MAX_SPDM_VERSION_COUNT; Index++) {
    if (Version == SpdmContext->ConnectionInfo.SpdmVersion[Index]) {
      return TRUE;
    }
  }
  return FALSE;
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
