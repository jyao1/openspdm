/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterTest.h"

#define SLOT_NUMBER    2

VOID                          *mSpdmContext;
SOCKET                        mSocket;

BOOLEAN
CommunicatePlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT32           Session,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend,
  OUT UINT32          *Response,
  OUT UINT32          *RspSession,
  IN OUT UINTN        *BytesToReceive,
  OUT UINT8           *ReceiveBuffer
  )
{
  BOOLEAN Result;

  Result = SendPlatformData (Socket, Command, Session, SendBuffer, BytesToSend);
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

  Result = ReceivePlatformData (Socket, Response, RspSession, ReceiveBuffer, BytesToReceive);
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

/**
  Send a SPDM request command to a device.

  @param  This                         Indicates a pointer to the calling context.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the request. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       request to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the request is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/
RETURN_STATUS
EFIAPI
SpdmClientSendRequest (
  IN     SPDM_IO_PROTOCOL        *This,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  BOOLEAN Result;

  Result = SendPlatformData (mSocket, SOCKET_SPDM_COMMAND_NORMAL, 0, Request, (UINT32)RequestSize);
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
  Receive a SPDM response from a device.

  @param  This                         Indicates a pointer to the calling context.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the response. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       response to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the response is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                          the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                          to execute.
**/
RETURN_STATUS
EFIAPI
SpdmClientReceiveResponse (
  IN     SPDM_IO_PROTOCOL        *This,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  BOOLEAN Result;
  UINT32  Command;
  UINT32  Session;

  Result = ReceivePlatformData (mSocket, &Command, &Session, Response, ResponseSize);
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
  if (Command != SOCKET_SPDM_COMMAND_NORMAL) {
    printf ("ReceivePlatformData Command Error - %x\n", Command);
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

/**
  Send a SPDM request command to a device.

  The request is a data blob to send to the messaging device directly,
  including session ID, length, encrypted message and MAC.
  The caller need use GetSecureMessagingType() to decide the format of the message.

  @param  This                         Indicates a pointer to the calling context.
  @param  RequestSize                  Size in bytes of the request data buffer.
  @param  Request                      A pointer to a destination buffer to store the request.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the request. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       request to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the request is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM request is sent successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM request is sent to the device.
  @retval RETURN_INVALID_PARAMETER        The Request is NULL or the RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM request
                                          to execute.
**/
RETURN_STATUS
EFIAPI
SpdmClientSecureSendRequest (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN     UINTN                                  RequestSize,
  IN     VOID                                   *Request,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;

  Result = SendPlatformData (mSocket, SOCKET_SPDM_COMMAND_SECURE, SessionId, Request, (UINT32)RequestSize);
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
  Receive a SPDM response from a device.

  The response is a data blob received from the messaging device directly,
  including session ID, length, encrypted message and MAC.
  The caller need use GetSecureMessagingType() to decide the format of the message.

  @param  This                         Indicates a pointer to the calling context.
  @param  ResponseSize                 Size in bytes of the response data buffer.
  @param  Response                     A pointer to a destination buffer to store the response.
                                       The caller is responsible for having
                                       either implicit or explicit ownership of the buffer.
  @param  Timeout                      The timeout, in 100ns units, to use for the execution
                                       of the response. A Timeout value of 0
                                       means that this function will wait indefinitely for the
                                       response to execute. If Timeout is greater
                                       than zero, then this function will return RETURN_TIMEOUT if the
                                       time required to execute the response is greater
                                       than Timeout.
                                       
  @retval RETURN_SUCCESS                  The SPDM response is received successfully.
  @retval RETURN_DEVICE_ERROR             A device error occurs when the SPDM response is received from the device.
  @retval RETURN_INVALID_PARAMETER        The Reponse is NULL, ResponseSize is NULL or
                                          the *RequestSize is zero.
  @retval RETURN_TIMEOUT                  A timeout occurred while waiting for the SPDM response
                                          to execute.
**/
RETURN_STATUS
EFIAPI
SpdmClientSecureReceiveResponse (
  IN     SPDM_IO_PROTOCOL                       *This,
  IN     UINT32                                 SessionId,
  IN OUT UINTN                                  *ResponseSize,
  IN OUT VOID                                   *Response,
  IN     UINT64                                 Timeout
  )
{
  BOOLEAN Result;
  UINT32  Command;
  UINT32  Session;

  Result = ReceivePlatformData (mSocket, &Command, &Session, Response, ResponseSize);
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
  if (Session != SessionId) {
    printf ("ReceivePlatformData Command Error - %x\n", Command);
    return RETURN_DEVICE_ERROR;
  }
  if (Command != SOCKET_SPDM_COMMAND_SECURE) {
    printf ("ReceivePlatformData Command Error - %x\n", Command);
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

SPDM_IO_PROTOCOL       mSpdmProtocol = {
  SpdmClientSendRequest,
  SpdmClientReceiveResponse,
  SpdmClientSecureSendRequest,
  SpdmClientSecureReceiveResponse,
  SpdmIoSecureMessagingTypeDmtfMtcp,
  sizeof(UINT32)
};

VOID
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
  SpdmContext = mSpdmContext;
  SpdmInitContext (SpdmContext);
  SpdmRegisterSpdmIo (SpdmContext, &mSpdmProtocol);

  Res = ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
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
    SpdmRegisterDataSignFunc (SpdmContext, SpdmDataSignFunc);
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
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
  if (!HasRspPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  }
  if (!HasReqPrivKey) {
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

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

  Status = SpdmInitConnection (SpdmContext);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmInitConnection - 0x%x\n", (UINT32)Status);
  }

  return ;
}