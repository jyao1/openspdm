/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequester.h"

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
SpdmRequesterSendMessage (
  IN     VOID                                   *SpdmContext,
  IN     UINT32                                 *SessionId,
  IN     UINTN                                  MessageSize,
  IN     VOID                                   *Message,
  IN     UINT64                                 Timeout
  )
{
  // Dummy
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
SpdmRequesterReceiveMessage (
  IN     VOID                                   *SpdmContext,
     OUT UINT32                                 **SessionId,
  IN OUT UINTN                                  *MessageSize,
  IN OUT VOID                                   *Message,
  IN     UINT64                                 Timeout
  )
{
  // Dummy
  return RETURN_SUCCESS;
}

VOID *
SpdmClientInit (
  VOID
  )
{
  VOID                         *SpdmContext;
  RETURN_STATUS                Status;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  BOOLEAN                      HasRspPubCert;

  SpdmContext = (VOID *)AllocatePool (SpdmGetContextSize());
  SpdmInitContext (SpdmContext);
  SpdmRegisterDeviceIoFunc (SpdmContext, SpdmRequesterSendMessage, SpdmRequesterReceiveMessage);
  SpdmRegisterTransportLayerFunc (SpdmContext, SpdmMctpEncodeMessage, SpdmMctpDecodeMessage);

  HasRspPubCert = FALSE;

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
//           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
//           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
           SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP;
  if (!HasRspPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG;
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    Data32 |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG;
    Data32 &= ~SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
  SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));

  Status = SpdmInitConnection (SpdmContext);
  if (RETURN_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "SpdmInitConnection - %r\n", Status));
    FreePool (SpdmContext);
    return NULL;
  }

  return SpdmContext;
}