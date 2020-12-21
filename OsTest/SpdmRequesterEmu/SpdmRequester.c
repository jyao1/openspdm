/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

#define SLOT_NUMBER    2

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
  BOOLEAN                      HasReqPubCert;
  BOOLEAN                      HasReqPrivKey;
  BOOLEAN                      HasRspPubCert;
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

  Res = ReadResponderRootPublicCertificate (&Data, &DataSize, &Hash, &HashSize);
  if (Res) {
    HasRspPubCert = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    //SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
    SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
    // Do not free it.
  } else{
    HasRspPubCert = FALSE;
  }

  Res = ReadRequesterPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  if (Res) {
    HasReqPubCert = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    Data8 = SLOT_NUMBER;
    SpdmSetData (SpdmContext, SpdmDataSlotCount, &Parameter, &Data8, sizeof(Data8));

    for (Index = 0; Index < SLOT_NUMBER; Index++) {
      Parameter.AdditionalData[0] = Index;
      SpdmSetData (SpdmContext, SpdmDataPublicCertChains, &Parameter, Data, DataSize);
    }
    // do not free it
  } else {
    HasReqPubCert = FALSE;
  }

  Res = ReadRequesterPrivateCertificate (&Data, &DataSize);
  if (Res) {
    HasReqPrivKey = TRUE;
    SpdmRegisterDataSignFunc (SpdmContext, SpdmRequesterDataSignFunc, SpdmResponderDataSignFunc);
  } else{
    HasReqPrivKey = FALSE;
  }

  Data8 = 0;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));

  Data32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
//           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  if (!HasRspPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG;
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG;
  }
  if (!HasReqPrivKey || !HasReqPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  }
  if (mUseCapabilityFlags != 0) {
    Data32 = mUseCapabilityFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data32 = mUseAsymAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = mUseHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data16 = mUseDheAlgo;
  SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
  Data16 = mUseAeadAlgo;
  SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
  Data16 = mUseReqAsymAlgo;
  SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof(Data16));
  Data16 = mUseKeyScheduleAlgo;
  SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));

  SpdmRegisterPskHkdfExpandFunc (SpdmContext, SpdmPskHandshakeSecretHkdfExpandFunc, SpdmPskMasterSecretHkdfExpandFunc);
  Status = SpdmSetData (SpdmContext, SpdmDataPskHint, NULL, TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
  }

  Status = SpdmInitConnection (SpdmContext);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmInitConnection - 0x%x\n", (UINT32)Status);
    free (mSpdmContext);
    mSpdmContext = NULL;
  }

  return mSpdmContext;
}