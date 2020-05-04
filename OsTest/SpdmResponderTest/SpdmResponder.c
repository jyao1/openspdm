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
  IN     UINT8                        SessionId,
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
  IN     UINT8                SessionId,
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

BOOLEAN
ProcessSpdmData (
  IN UINT32     Command,
  IN VOID       *RequestBuffer,
  IN UINTN      RequestBufferSize,
  OUT VOID      *ResponseBuffer,
  IN OUT UINTN  *ResponseBufferSize
  )
{
  VOID                  *SpdmContext;
  RETURN_STATUS         Status;

  SpdmContext = mSpdmContext;

  if (Command == SOCKET_SPDM_COMMAND_NORMAL) {
    Status = SpdmReceiveSendData (SpdmContext, RequestBuffer, RequestBufferSize, ResponseBuffer, ResponseBufferSize);
  } else {
    Status = SpdmReceiveSendSessionData (SpdmContext, GET_COMMAND_SESSION_ID(Command), RequestBuffer, RequestBufferSize, ResponseBuffer, ResponseBufferSize);
  }
  if (RETURN_ERROR(Status)) {
    return FALSE;
  }
  return TRUE;
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
  EDKII_SPDM_DATA_PARAMETER    Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  BOOLEAN                      HasPubCert;
  BOOLEAN                      HasPrivKey;

  mSpdmContext = malloc (SpdmGetContextSize());
  SpdmContext = mSpdmContext;
  SpdmInitContext (SpdmContext);

  Res = ReadPublicCertificateChain (&Data, &DataSize);
  if (Res) {
    HasPubCert = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = EdkiiSpdmDataLocationLocal;
    Data8 = SLOT_NUMBER;
    SpdmSetData (SpdmContext, EdkiiSpdmSlotCount, &Parameter, &Data8, sizeof(Data8));

    for (Index = 0; Index < SLOT_NUMBER; Index++) {
      Parameter.AdditionalData[0] = Index;
      SpdmSetData (SpdmContext, EdkiiSpdmPublicCertChains, &Parameter, Data, DataSize);
    }
    // do not free it
  } else {
    HasPubCert = FALSE;
  }

  Res = ReadPrivateCertificate (&Data, &DataSize);
  if (Res) {
    HasPrivKey = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = EdkiiSpdmDataLocationLocal;
    SpdmSetData (SpdmContext, EdkiiSpdmPrivateCertificate, &Parameter, Data, DataSize);
    // do not free it
  } else{
    HasPrivKey = FALSE;
  }

  Data8 = 0;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = EdkiiSpdmDataLocationLocal;
  SpdmSetData (SpdmContext, EdkiiSpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));

  Data32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP |
           SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  if (!HasPubCert) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  }
  if (!HasPrivKey) {
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  } else {
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
    Data32 |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
    Data32 &= ~SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG;
  }
  SpdmSetData (SpdmContext, EdkiiSpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmSetData (SpdmContext, EdkiiSpdmDataMeasurementHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048;
  SpdmSetData (SpdmContext, EdkiiSpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;
  SpdmSetData (SpdmContext, EdkiiSpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
  SpdmSetData (SpdmContext, EdkiiSpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, EdkiiSpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
  Data16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  SpdmSetData (SpdmContext, EdkiiSpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));

  Res = RegisterMeasurement (&Data, &DataSize, &Data8);
  if (Res) {
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = EdkiiSpdmDataLocationLocal;
    Parameter.AdditionalData[0] = Data8;
    SpdmSetData (SpdmContext, EdkiiSpdmMeasurementRecord, &Parameter, Data, DataSize);
    // do not free it
  }

  Status = SpdmRegisterGetResponseSessionFunc (SpdmContext, SpdmGetResponseVendorDefinedRequest);

#if USE_PSK
  Status = SpdmSetData (SpdmContext, EdkiiSpdmDataPsk, NULL, "TestPskData", sizeof("TestPskData"));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
    return ;
  }
#endif

  return ;
}