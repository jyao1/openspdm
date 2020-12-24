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

  Data8 = 0;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));

  Data32 = mUseResonderCapabilityFlags;
  if (mUseCapabilityFlags != 0) {
    Data32 = mUseCapabilityFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

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

  return mSpdmContext;
}

VOID
SpdmServerCallback (
  VOID
  )
{
  VOID                         *SpdmContext;
  STATIC BOOLEAN               AlgoProvisioned = FALSE;
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

  SpdmContext = mSpdmContext;

  if (AlgoProvisioned) {
    return ;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;

  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataConnectionState, &Parameter, &Data32, &DataSize);
  if (Data32 != SpdmConnectionStateNegotiated) {
    return ;
  }

  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, &DataSize);
  mUseAsymAlgo = Data32;
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, &DataSize);
  mUseHashAlgo = Data32;
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, &DataSize);
  mUseMeasurementHashAlgo = Data32;
  DataSize = sizeof(Data16);
  SpdmGetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, &DataSize);
  mUseReqAsymAlgo = Data16;

  Res = ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    Data8 = mUseSlotCount;
    SpdmSetData (SpdmContext, SpdmDataSlotCount, &Parameter, &Data8, sizeof(Data8));

    for (Index = 0; Index < mUseSlotCount; Index++) {
      Parameter.AdditionalData[0] = Index;
      SpdmSetData (SpdmContext, SpdmDataPublicCertChains, &Parameter, Data, DataSize);
    }
    // do not free it
  }

  Res = ReadResponderPrivateCertificate (&Data, &DataSize);
  if (Res) {
    SpdmRegisterDataSignFunc (SpdmContext, SpdmRequesterDataSignFunc, SpdmResponderDataSignFunc);
  }

  Res = ReadRequesterRootPublicCertificate (&Data, &DataSize, &Hash, &HashSize);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    //SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
    SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
    // Do not free it.

    Data8 = mUseMutAuth;
    if (Data8 != 0) {
      Data8 |= SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    }
    Parameter.AdditionalData[0] = mUseSlotId; // SlotNum;
    Parameter.AdditionalData[1] = mUseMeasurementSummaryHashType; // MeasurementHashType;
    SpdmSetData (SpdmContext, SpdmDataMutAuthRequested, &Parameter, &Data8, sizeof(Data8));

    Data8 = (mUseMutAuth & 0x1);
    SpdmSetData (SpdmContext, SpdmDataBasicMutAuthRequested, &Parameter, &Data8, sizeof(Data8));
  }

  Res = ReadMeasurementData (&Data, &DataSize, &Data8);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    Parameter.AdditionalData[0] = Data8;
    SpdmSetData (SpdmContext, SpdmDataMeasurementRecord, &Parameter, Data, DataSize);
    // do not free it
  }

  SpdmRegisterPskHkdfExpandFunc (SpdmContext, SpdmPskHandshakeSecretHkdfExpandFunc, SpdmPskMasterSecretHkdfExpandFunc);
  Status = SpdmSetData (SpdmContext, SpdmDataPskHint, NULL, TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
  }

  AlgoProvisioned = TRUE;

  return ;
}