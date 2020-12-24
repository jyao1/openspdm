/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

VOID                          *mSpdmContext;
SOCKET                        mSocket;

BOOLEAN
CommunicatePlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend,
  OUT UINT32          *Response,
  IN OUT UINTN        *BytesToReceive,
  OUT UINT8           *ReceiveBuffer
  )
{
  BOOLEAN Result;

  Result = SendPlatformData (Socket, Command, SendBuffer, BytesToSend);
  if (!Result) {
    printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return Result;
  }

  Result = ReceivePlatformData (Socket, Response, ReceiveBuffer, BytesToReceive);
  if (!Result) {
    printf ("ReceivePlatformData Error - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return Result;
  }
  return Result;
}

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

  Result = SendPlatformData (mSocket, SOCKET_SPDM_COMMAND_NORMAL, Request, (UINT32)RequestSize);
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
  UINT32  Command;

  Result = ReceivePlatformData (mSocket, &Command, Response, ResponseSize);
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
  return RETURN_SUCCESS;
}

VOID *
SpdmClientInit (
  VOID
  )
{
  VOID                         *SpdmContext;
  UINT8                        Index;
  RETURN_STATUS                Status;
  BOOLEAN                      Res;
  VOID                         *Data;
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  VOID                         *Hash;
  UINTN                        HashSize;

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

  Data32 = mUseRequesterCapabilityFlags;
  if (mUseCapabilityFlags != 0) {
    Data32 = mUseCapabilityFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

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

  Status = SpdmInitConnection (SpdmContext);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmInitConnection - 0x%x\n", (UINT32)Status);
    free (mSpdmContext);
    mSpdmContext = NULL;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataConnectionState, &Parameter, &Data32, &DataSize);
  ASSERT (Data32 == SpdmConnectionStateNegotiated);

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

  if (mUseSlotId == 0xFF) {
    Res = ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
    if (Res) {
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationLocal;
      SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
      // Do not free it.
    }
  } else {
    Res = ReadResponderRootPublicCertificate (&Data, &DataSize, &Hash, &HashSize);
    if (Res) {
      ZeroMem (&Parameter, sizeof(Parameter));
      Parameter.Location = SpdmDataLocationLocal;
      SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
      // Do not free it.
    }
  }


  Res = ReadRequesterPublicCertificateChain (&Data, &DataSize, NULL, NULL);
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

  Res = ReadRequesterPrivateCertificate (&Data, &DataSize);
  if (Res) {
    SpdmRegisterDataSignFunc (SpdmContext, SpdmRequesterDataSignFunc, SpdmResponderDataSignFunc);
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

  return mSpdmContext;
}