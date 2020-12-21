/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderEmu.h"

#define SLOT_NUMBER    2

VOID                              *mSpdmContext;

SPDM_VENDOR_DEFINED_REQUEST_MINE  mVendorDefinedResponse = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_RESPONSE,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_TEST, // StandardID
  2, // Len
  SPDM_TEST_VENDOR_ID_HELLO, // VendorID
  TEST_PAYLOAD_LEN, // PayloadLength
  {TEST_PAYLOAD_SERVER}
};

extern UINT32 mCommand;
extern UINTN  mReceiveBufferSize;
extern UINT8  mReceiveBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern SOCKET mServerSocket;

BOOLEAN
RegisterMeasurement (
  OUT VOID                            **DeviceMeasurement,
  OUT UINTN                           *DeviceMeasurementSize,
  OUT UINT8                           *DeviceMeasurementCount
  );

/**
  Process a packet in the current SPDM session.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    ID of the session.
  @param  Request                      A pointer to the request data.
  @param  RequestSize                  Size of the request data.
  @param  Response                     A pointer to the response data.
  @param  ResponseSize                 Size of the response data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM request is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/
RETURN_STATUS
EFIAPI
TestSpdmProcessPacketCallback (
  IN     UINT32                       *SessionId,
  IN     BOOLEAN                      IsAppMessage,
  IN     VOID                         *Request,
  IN     UINTN                        RequestSize,
     OUT VOID                         *Response,
  IN OUT UINTN                        *ResponseSize
  )
{
  SPDM_VENDOR_DEFINED_REQUEST_MINE   *SpmdRequest;

  if (!IsAppMessage) {
    SpmdRequest = Request;
    ASSERT ((RequestSize >= sizeof(SPDM_VENDOR_DEFINED_REQUEST_MINE)) && (RequestSize < sizeof(SPDM_VENDOR_DEFINED_REQUEST_MINE) + 4));
    ASSERT (SpmdRequest->Header.RequestResponseCode == SPDM_VENDOR_DEFINED_REQUEST);
    ASSERT (SpmdRequest->StandardID == SPDM_REGISTRY_ID_TEST);
    ASSERT (SpmdRequest->VendorID == SPDM_TEST_VENDOR_ID_HELLO);
    ASSERT (SpmdRequest->PayloadLength == TEST_PAYLOAD_LEN);
    ASSERT (CompareMem (SpmdRequest->VendorDefinedPayload, TEST_PAYLOAD_CLIENT, TEST_PAYLOAD_LEN) == 0);

    CopyMem (Response, &mVendorDefinedResponse, sizeof(mVendorDefinedResponse));
    *ResponseSize = sizeof(mVendorDefinedResponse);
  } else {
    ASSERT (RequestSize == TEST_PAYLOAD_LEN);
    ASSERT (CompareMem (Request, TEST_PAYLOAD_CLIENT, TEST_PAYLOAD_LEN) == 0);

    CopyMem (Response, TEST_PAYLOAD_SERVER, TEST_PAYLOAD_LEN);
    *ResponseSize = TEST_PAYLOAD_LEN;
  }

  return RETURN_SUCCESS;
}

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
  )
{
  RETURN_STATUS  Status;

  Status = TestSpdmProcessPacketCallback (
             SessionId,
             IsAppMessage,
             Request,
             RequestSize,
             Response,
             ResponseSize
             );
  if (RETURN_ERROR(Status)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
  }
  return RETURN_SUCCESS;
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
  UINT8                        Index;
  RETURN_STATUS                Status;
  BOOLEAN                      Res;
  VOID                         *Data;
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  BOOLEAN                      HasRspPubCert;
  BOOLEAN                      HasRspPrivKey;
  BOOLEAN                      HasReqPubCert;
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

  Res = ReadResponderPublicCertificateChain (&Data, &DataSize, NULL, NULL);
  if (Res) {
    HasRspPubCert = TRUE;
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
    HasRspPubCert = FALSE;
  }

  Res = ReadResponderPrivateCertificate (&Data, &DataSize);
  if (Res) {
    HasRspPrivKey = TRUE;
    SpdmRegisterDataSignFunc (SpdmContext, SpdmRequesterDataSignFunc, SpdmResponderDataSignFunc);
  } else{
    HasRspPrivKey = FALSE;
  }

  Res = ReadRequesterRootPublicCertificate (&Data, &DataSize, &Hash, &HashSize);
  if (Res) {
    HasReqPubCert = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    //SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
    SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
    // Do not free it.

    //Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
    //Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED | SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;
    Parameter.AdditionalData[0] = 0; // SlotNum;
    Parameter.AdditionalData[1] = 0; // MeasurementHashType;
    SpdmSetData (SpdmContext, SpdmDataMutAuthRequested, &Parameter, &Data8, sizeof(Data8));
  } else{
    HasReqPubCert = FALSE;
  }

  Data8 = 0;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));

  Data32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
//           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
//           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  if (!HasRspPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  }
  if (!HasRspPrivKey) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  }
  if (!HasReqPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP;
  }
  if (mUseCapabilityFlags != 0) {
    Data32 = mUseCapabilityFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data32 = mUseMeasurementHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, sizeof(Data32));
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

  Res = RegisterMeasurement (&Data, &DataSize, &Data8);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    Parameter.AdditionalData[0] = Data8;
    SpdmSetData (SpdmContext, SpdmDataMeasurementRecord, &Parameter, Data, DataSize);
    // do not free it
  }

  SpdmRegisterGetResponseFunc (SpdmContext, SpdmGetResponseVendorDefinedRequest);

  SpdmRegisterPskHkdfExpandFunc (SpdmContext, SpdmPskHandshakeSecretHkdfExpandFunc, SpdmPskMasterSecretHkdfExpandFunc);
  Status = SpdmSetData (SpdmContext, SpdmDataPskHint, NULL, TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
  }

  return mSpdmContext;
}