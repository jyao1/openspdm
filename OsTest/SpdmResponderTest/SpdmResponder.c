/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderTest.h"

#define SLOT_NUMBER    2

VOID                              *mSpdmContext;

SPDM_VENDOR_DEFINED_REQUEST_MINE  mVendorDefinedResponse = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_RESPONSE,
    0, // Param1
    0, // Param2
  },
  SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_PCISIG, // StandardID
  2, // Len
  0x8086, // VendorID
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
  IN     UINT32                       SessionId,
  IN     VOID                         *Request,
  IN     UINTN                        RequestSize,
     OUT VOID                         *Response,
  IN OUT UINTN                        *ResponseSize
  )
{
  SPDM_VENDOR_DEFINED_REQUEST_MINE   *SpmdRequest;
  SpmdRequest = Request;
  ASSERT (RequestSize == sizeof(SPDM_VENDOR_DEFINED_REQUEST_MINE));
  ASSERT (SpmdRequest->Header.RequestResponseCode == SPDM_VENDOR_DEFINED_REQUEST);
  ASSERT (SpmdRequest->StandardID == SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_PCISIG);
  ASSERT (SpmdRequest->VendorID == 0x8086);
  ASSERT (SpmdRequest->PayloadLength == TEST_PAYLOAD_LEN);
  ASSERT (CompareMem (SpmdRequest->VendorDefinedPayload, TEST_PAYLOAD_CLIENT, TEST_PAYLOAD_LEN) == 0);

  CopyMem (Response, &mVendorDefinedResponse, sizeof(mVendorDefinedResponse));
  *ResponseSize = sizeof(mVendorDefinedResponse);
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmGetResponseVendorDefinedRequest (
  IN     VOID                *SpdmContext,
  IN     UINT32               SessionId,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  RETURN_STATUS  Status;

  Status = TestSpdmProcessPacketCallback (
             SessionId,
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

/**
  Send a SPDM message to a device.

  For requester, the message is an SPDM request.
  For responder, the message is an SPDM response.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is sent successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is sent to the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
RETURN_STATUS
EFIAPI
SpdmDeviceSendMessage (
  IN     UINT32                                 *SessionId,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;

  if (SessionId == NULL) {
    Result = SendPlatformData (mServerSocket, SOCKET_SPDM_COMMAND_NORMAL, 0, Request, (UINT32)RequestSize);
  } else {
    Result = SendPlatformData (mServerSocket, SOCKET_SPDM_COMMAND_SECURE, *SessionId, Request, (UINT32)RequestSize);
  }
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

/**
  Receive a SPDM message from a device.

  For requester, the message is an SPDM response.
  For responder, the message is an SPDM request.

  @param  This                         Indicates a pointer to the calling context.
  @param  SessionId                    The SessionId of a SPDM message.
                                       If *SessionId is NULL, it is a normal message.
                                       If *SessionId is NOT NULL, it is a secure message.
  @param  MessageSize                  Size in bytes of the message data buffer.
  @param  Message                      A pointer to a destination buffer to store the message.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the message. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       message to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the message is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS               The SPDM message is received successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when the SPDM message is received from the device.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL, MessageSize is NULL or
                                       the *MessageSize is zero.
  @retval RETURN_TIMEOUT               A timeout occurred while waiting for the SPDM message
                                       to execute.
**/
RETURN_STATUS
EFIAPI
SpdmDeviceReceiveMessage (
     OUT UINT32                                 **SessionId,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;
  UINT32  Session;

  mReceiveBufferSize = sizeof(mReceiveBuffer);
  Result = ReceivePlatformData (mServerSocket, &mCommand, &Session, mReceiveBuffer, &mReceiveBufferSize);
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
    *SessionId = NULL;
  } else if (mCommand == SOCKET_SPDM_COMMAND_SECURE) {
    *SessionId = &Session;
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

VOID
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
  SpdmContext = mSpdmContext;
  SpdmInitContext (SpdmContext);

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
    SpdmRegisterDataSignFunc (SpdmContext, SpdmDataSignFunc);
  } else{
    HasRspPrivKey = FALSE;
  }

  Res = ReadRequesterPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  if (Res) {
    HasReqPubCert = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    //SpdmSetData (SpdmContext, SpdmDataPeerPublicCertChains, &Parameter, Data, DataSize);
    SpdmSetData (SpdmContext, SpdmDataPeerPublicRootCertHash, &Parameter, Hash, HashSize);
    // Do not free it.
    
    Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED;
    //Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST;
    //Data8 = SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS;
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
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP;
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
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmSetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = USE_ASYM_ALGO;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = USE_HASH_ALGO;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data16 = USE_DHE_ALGO;
  SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
  Data16 = USE_AEAD_ALGO;
  SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
  Data16 = USE_REQ_ASYM_ALGO;
  SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof(Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));

  Res = RegisterMeasurement (&Data, &DataSize, &Data8);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    Parameter.AdditionalData[0] = Data8;
    SpdmSetData (SpdmContext, SpdmDataMeasurementRecord, &Parameter, Data, DataSize);
    // do not free it
  }

  Status = SpdmRegisterGetResponseSessionFunc (SpdmContext, SpdmGetResponseVendorDefinedRequest);
  if (RETURN_ERROR(Status)) {
  }

  Status = SpdmSetData (SpdmContext, SpdmDataPsk, NULL, "TestPskData", sizeof("TestPskData"));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
    return ;
  }
  Status = SpdmSetData (SpdmContext, SpdmDataPskHint, NULL, "TestPskHint", sizeof("TestPskHint"));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
    return ;
  }

  return ;
}