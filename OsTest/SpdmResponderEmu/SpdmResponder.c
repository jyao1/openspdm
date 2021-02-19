/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderEmu.h"

VOID                              *mSpdmContext;

extern UINT32 mCommand;
extern UINTN  mReceiveBufferSize;
extern UINT8  mReceiveBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern SOCKET mServerSocket;

/**
  Notify the session state to a session APP.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SessionId of a session.
  @param  SessionState                 The state of a session.
**/
VOID
EFIAPI
SpdmServerSessionStateCallback (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     SPDM_SESSION_STATE   SessionState
  );

/**
  Notify the connection state to an SPDM context register.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ConnectionState              Indicate the SPDM connection state.
**/
VOID
EFIAPI
SpdmServerConnectionStateCallback (
  IN     VOID                     *SpdmContext,
  IN     SPDM_CONNECTION_STATE    ConnectionState
  );

RETURN_STATUS
EFIAPI
SpdmGetResponseVendorDefinedRequest (
  IN     VOID                *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsAppMessage,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  );

RETURN_STATUS
EFIAPI
SpdmDeviceSendMessage (
  IN     VOID                                   *SpdmContext,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;

  Result = SendPlatformData (mServerSocket, SOCKET_SPDM_COMMAND_NORMAL, Request, (UINT32)RequestSize);
  if (!Result) {
    printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmDeviceReceiveMessage (
  IN     VOID                                   *SpdmContext,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;

  mReceiveBufferSize = sizeof(mReceiveBuffer);
  Result = ReceivePlatformData (mServerSocket, &mCommand, mReceiveBuffer, &mReceiveBufferSize);
  if (!Result) {
    printf ("ReceivePlatformData Error - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return RETURN_DEVICE_ERROR;
  }
  if (mCommand == SOCKET_SPDM_COMMAND_NORMAL) {
    //
    // Cache the message in case it is not for SPDM.
    //
  } else {
    //
    // Cache the message
    //
    return RETURN_UNSUPPORTED;
  }
  if (*ResponseSize < mReceiveBufferSize) {
    *ResponseSize = mReceiveBufferSize;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *ResponseSize = mReceiveBufferSize;
  CopyMem (Response, mReceiveBuffer, mReceiveBufferSize);
  return RETURN_SUCCESS;
}

VOID *
SpdmServerInit (
  VOID
  )
{
  VOID                         *SpdmContext;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  SPDM_VERSION_NUMBER          SpdmVersion;

  mSpdmContext = (VOID *)malloc (SpdmGetContextSize());
  if (mSpdmContext == NULL) {
    return NULL;
  }
  SpdmContext = mSpdmContext;
  SpdmInitContext (SpdmContext);
  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmDeviceSendMessage, SpdmDeviceReceiveMessage);
  if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
    SpdmRegisterTransportLayerFunc (SpdmContext, SpdmTransportMctpEncodeMessage, SpdmTransportMctpDecodeMessage);
  } else if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    SpdmRegisterTransportLayerFunc (SpdmContext, SpdmTransportPciDoeEncodeMessage, SpdmTransportPciDoeDecodeMessage);
  } else {
    return NULL;
  }

  if (mLoadStateFileName != NULL) {
    SpdmLoadNegotiatedState (SpdmContext, FALSE);
  }

  if (mUseVersion != SPDM_MESSAGE_VERSION_11) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    SpdmVersion.MajorVersion = (mUseVersion >> 4) & 0xF;
    SpdmVersion.MinorVersion = mUseVersion & 0xF;
    SpdmVersion.Alpha = 0;
    SpdmVersion.UpdateVersionNumber = 0;
    SpdmSetData (SpdmContext, SpdmDataSpdmVersion, &Parameter, &SpdmVersion, sizeof(SpdmVersion));
  }

  if (mUseSecuredMessageVersion != SPDM_MESSAGE_VERSION_11) {
    ZeroMem (&Parameter, sizeof(Parameter));
    if (mUseSecuredMessageVersion != 0) {
      Parameter.Location = SpdmDataLocationLocal;
      SpdmVersion.MajorVersion = (mUseSecuredMessageVersion >> 4) & 0xF;
      SpdmVersion.MinorVersion = mUseSecuredMessageVersion & 0xF;
      SpdmVersion.Alpha = 0;
      SpdmVersion.UpdateVersionNumber = 0;
      SpdmSetData (SpdmContext, SpdmDataSecuredMessageVersion, &Parameter, &SpdmVersion, sizeof(SpdmVersion));
    } else {
      SpdmSetData (SpdmContext, SpdmDataSecuredMessageVersion, &Parameter, NULL, 0);
    }
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;

  Data8 = 0;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));
  Data32 = mUseResponderCapabilityFlags;
  if (mUseCapabilityFlags != 0) {
    Data32 = mUseCapabilityFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data8 = mSupportMeasurementSpec;
  SpdmSetData (SpdmContext, SpdmDataMeasurementSpec, &Parameter, &Data8, sizeof(Data8));
  Data32 = mSupportMeasurementHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = mSupportAsymAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = mSupportHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data16 = mSupportDheAlgo;
  SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
  Data16 = mSupportAeadAlgo;
  SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
  Data16 = mSupportReqAsymAlgo;
  SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof(Data16));
  Data16 = mSupportKeyScheduleAlgo;
  SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));

  SpdmRegisterGetResponseFunc (SpdmContext, SpdmGetResponseVendorDefinedRequest);

  SpdmRegisterSessionStateCallback (SpdmContext, SpdmServerSessionStateCallback);
  SpdmRegisterConnectionStateCallback (SpdmContext, SpdmServerConnectionStateCallback);

  if (mLoadStateFileName != NULL) {
    // Invoke callback to provision the rest
    SpdmServerConnectionStateCallback (SpdmContext, SpdmConnectionStateNegotiated);
  }

  return mSpdmContext;
}

/**
  Notify the connection state to an SPDM context register.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  ConnectionState              Indicate the SPDM connection state.
**/
VOID
EFIAPI
SpdmServerConnectionStateCallback (
  IN     VOID                     *SpdmContext,
  IN     SPDM_CONNECTION_STATE    ConnectionState
  )
{
  BOOLEAN                      Res;
  VOID                         *Data;
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  RETURN_STATUS                Status;
  VOID                         *Hash;
  UINTN                        HashSize;
  UINT8                        Index;

  switch (ConnectionState) {
  case SpdmConnectionStateNotStarted:
    //
    // clear perserved state
    //  
    if (mSaveStateFileName != NULL) {
      SpdmClearNegotiatedState (SpdmContext);
    }
    break;

  case SpdmConnectionStateNegotiated:
    //
    // Provision new content
    //
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationConnection;

    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, &DataSize);
    mUseMeasurementHashAlgo = Data32;
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, &DataSize);
    mUseAsymAlgo = Data32;
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, &DataSize);
    mUseHashAlgo = Data32;
    DataSize = sizeof(Data16);
    SpdmGetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, &DataSize);
    mUseReqAsymAlgo = Data16;

    Res = ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
    if (Res) {
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationLocal;
      Data8 = mUseSlotCount;
      SpdmSetData (SpdmContext, SpdmDataLocalSlotCount, &Parameter, &Data8, sizeof(Data8));

      for (Index = 0; Index < mUseSlotCount; Index++) {
        Parameter.AdditionalData[0] = Index;
        SpdmSetData (SpdmContext, SpdmDataLocalPublicCertChain, &Parameter, Data, DataSize);
      }
      // do not free it
    }

    if ((mUseSlotId == 0xFF) || ((mUseResponderCapabilityFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP) != 0)) {
      Res = ReadRequesterPublicCertificateChain (mUseHashAlgo, mUseReqAsymAlgo, &Data, &DataSize, NULL, NULL);
      if (Res) {
        ZeroMem (&Parameter, sizeof(Parameter));
        Parameter.Location = SpdmDataLocationLocal;
        SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
        // Do not free it.
      }
    } else {
      Res = ReadRequesterRootPublicCertificate (mUseHashAlgo, mUseReqAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
      if (Res) {
        ZeroMem (&Parameter, sizeof(Parameter));
        Parameter.Location = SpdmDataLocationLocal;
        SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
        // Do not free it.
      }
    }

    if (Res) {
      Data8 = mUseMutAuth;
      Parameter.AdditionalData[0] = mUseSlotId; // ReqSlotNum;
      SpdmSetData (SpdmContext, SpdmDataMutAuthRequested, &Parameter, &Data8, sizeof(Data8));

      Data8 = mUseBasicMutAuth;
      Parameter.AdditionalData[0] = mUseSlotId; // ReqSlotNum;
      SpdmSetData (SpdmContext, SpdmDataBasicMutAuthRequested, &Parameter, &Data8, sizeof(Data8));
    }

    Status = SpdmSetData (SpdmContext, SpdmDataPskHint, NULL, TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
    if (RETURN_ERROR(Status)) {
      printf ("SpdmSetData - %x\n", (UINT32)Status);
    }

    if (mSaveStateFileName != NULL) {
      SpdmSaveNegotiatedState (SpdmContext, FALSE);
    }

    break;

  default:
    break;
  }

  return ;
}

/**
  Notify the session state to a session APP.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The SessionId of a session.
  @param  SessionState                 The state of a session.
**/
VOID
EFIAPI
SpdmServerSessionStateCallback (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     SPDM_SESSION_STATE   SessionState
  )
{
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;

  switch (SessionState) {
  case SpdmSessionStateNotStarted :
    // Session End

    if (mSaveStateFileName != NULL) {
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationSession;
      *(UINT32 *)Parameter.AdditionalData = SessionId;

      DataSize = sizeof(Data8);
      SpdmGetData (SpdmContext, SpdmDataSessionEndSessionAttributes, &Parameter, &Data8, &DataSize);
      if ((Data8 & SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR) != 0) {
        // clear
        SpdmClearNegotiatedState (SpdmContext);
      } else {
        // preserve - already done in SpdmConnectionStateNegotiated.
        // SpdmSaveNegotiatedState (SpdmContext, FALSE);
      }
    }
    break;

  case SpdmSessionStateHandshaking :
    // no action
    break;

  case SpdmSessionStateEstablished :
    // no action
    break;

  default :
    ASSERT(FALSE);
    break;
  }
}
