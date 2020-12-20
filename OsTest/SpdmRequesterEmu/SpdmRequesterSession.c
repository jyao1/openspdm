/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

extern VOID          *mSpdmContext;

typedef struct {
  SPDM_DEBUG_DATA_TYPE  DataType;
  CHAR8                 *String;
} DATA_TYPE_STRING;

DATA_TYPE_STRING  mDataTypeString[] = {
#if 0
  {SpdmDataDheSecret,                       "DheSecret"},
  {SpdmDataHandshakeSecret,                 "HandshakeSecret"},
  {SpdmDataMasterSecret,                    "MasterSecret"},
  {SpdmDataRequestHandshakeSecret,          "RequestHandshakeSecret"},
  {SpdmDataResponseHandshakeSecret,         "ResponseHandshakeSecret"},
  {SpdmDataRequestDataSecret,               "RequestDataSecret"},
  {SpdmDataResponseDataSecret,              "ResponseDataSecret"},
  {SpdmDataRequestFinishedKey,              "RequestFinishedKey"},
  {SpdmDataResponseFinishedKey,             "ResponseFinishedKey"},
#endif
  {SpdmDataExportMasterSecret,              "ExportMasterSecret"},
  {SpdmDataRequestHandshakeEncryptionKey,   "RequestHandshakeEncryptionKey"},
  {SpdmDataRequestHandshakeSalt,            "RequestHandshakeSalt"},
  {SpdmDataResponseHandshakeEncryptionKey,  "ResponseHandshakeEncryptionKey"},
  {SpdmDataResponseHandshakeSalt,           "ResponseHandshakeSalt"},
  {SpdmDataRequestDataEncryptionKey,        "RequestDataEncryptionKey"},
  {SpdmDataRequestDataSalt,                 "RequestDataSalt"},
  {SpdmDataResponseDataEncryptionKey,       "ResponseDataEncryptionKey"},
  {SpdmDataResponseDataSalt,                "ResponseDataSalt"},
  {SpdmDataRequestHandshakeSequenceNumber,  "RequestHandshakeSequenceNumber"},
  {SpdmDataResponseHandshakeSequenceNumber, "ResponseHandshakeSequenceNumber"},
  {SpdmDataRequestDataSequenceNumber,       "RequestDataSequenceNumber"},
  {SpdmDataResponseDataSequenceNumber,      "ResponseDataSequenceNumber"},
};

SPDM_VENDOR_DEFINED_REQUEST_MINE  mVendorDefinedRequest = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_REQUEST,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_TEST, // StandardID
  2, // Len
  SPDM_TEST_VENDOR_ID_HELLO, // VendorID
  TEST_PAYLOAD_LEN, // PayloadLength
  {TEST_PAYLOAD_CLIENT}
};

RETURN_STATUS
DoAppSessionViaSpdm (
  IN UINT32                          SessionId
  )
{
  VOID                               *SpdmContext;
  RETURN_STATUS                      Status;
  SPDM_VENDOR_DEFINED_REQUEST_MINE   Request;
  UINTN                              RequestSize;
  SPDM_VENDOR_DEFINED_RESPONSE_MINE  Response;
  UINTN                              ResponseSize;
  UINT8                              AppResponse[TEST_PAYLOAD_LEN];
  UINTN                              AppResponseSize;

  SpdmContext = mSpdmContext;

  CopyMem (&Request, &mVendorDefinedRequest, sizeof(Request));

  RequestSize = sizeof(Request);
  ResponseSize = sizeof(Response);
  Status = SpdmSendReceiveData (SpdmContext, &SessionId, FALSE, &Request, RequestSize, &Response, &ResponseSize);
  ASSERT_RETURN_ERROR(Status);

  ASSERT (ResponseSize == sizeof(SPDM_VENDOR_DEFINED_RESPONSE_MINE));
  ASSERT (Response.Header.RequestResponseCode == SPDM_VENDOR_DEFINED_RESPONSE);
  ASSERT (Response.StandardID == SPDM_REGISTRY_ID_TEST);
  ASSERT (Response.VendorID == SPDM_TEST_VENDOR_ID_HELLO);
  ASSERT (Response.PayloadLength == TEST_PAYLOAD_LEN);
  ASSERT (CompareMem (Response.VendorDefinedPayload, TEST_PAYLOAD_SERVER, TEST_PAYLOAD_LEN) == 0);

  if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
    AppResponseSize = sizeof(AppResponse);
    Status = SpdmSendReceiveData (SpdmContext, &SessionId, TRUE, TEST_PAYLOAD_CLIENT, TEST_PAYLOAD_LEN, &AppResponse, &AppResponseSize);
    ASSERT_RETURN_ERROR(Status);

    ASSERT (AppResponseSize == TEST_PAYLOAD_LEN);
    ASSERT (CompareMem (AppResponse, TEST_PAYLOAD_SERVER, TEST_PAYLOAD_LEN) == 0);
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
DoSessionViaSpdm (
  VOID
  )
{
  VOID                             *SpdmContext;
  RETURN_STATUS                    Status;
  UINTN                            DataSize;
  UINT8                            Data[MAX_DHE_KEY_SIZE];
  UINTN                            Index;
  UINT32                           SessionId;
  UINT32                           SessionId2;
  SPDM_DATA_PARAMETER              Parameter;
  UINT8                            HeartbeatPeriod;
  UINT8                            MeasurementHash[MAX_HASH_SIZE];

  SpdmContext = mSpdmContext;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             FALSE, // KeyExchange
             SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
             0,
             &SessionId,
             &HeartbeatPeriod,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStartSession - %x\n", (UINT32)Status);
    return Status;
  }
  
  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             TRUE, // PSK
             SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
             0,
             &SessionId2,
             &HeartbeatPeriod,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStartSession - %x\n", (UINT32)Status);
    return Status;
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = SessionId;
  for (Index = 0; Index < ARRAY_SIZE(mDataTypeString); Index++) {
    DataSize = sizeof(Data);
    ZeroMem (Data, sizeof(Data));
    Status = SpdmGetData (SpdmContext, (SPDM_DATA_TYPE)mDataTypeString[Index].DataType, &Parameter, Data, &DataSize);
    if (!RETURN_ERROR(Status)) {
      printf ("%s (%d) - ", mDataTypeString[Index].String, (UINT32)DataSize);
      DumpData (Data, DataSize);
      printf ("\n");
    } else {
      printf ("%s - %x\n", mDataTypeString[Index].String, (UINT32)Status);
    }
  }

  DoAppSessionViaSpdm (SessionId);

  DoAppSessionViaSpdm (SessionId2);

  Status = SpdmHeartbeat (SpdmContext, SessionId);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmHeartbeat - %x\n", (UINT32)Status);
  }

  Status = SpdmHeartbeat (SpdmContext, SessionId2);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmHeartbeat - %x\n", (UINT32)Status);
  }

  Status = SpdmKeyUpdate (SpdmContext, SessionId, TRUE);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmKeyUpdate - %x\n", (UINT32)Status);
  }

  Status = SpdmKeyUpdate (SpdmContext, SessionId2, FALSE);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmKeyUpdate - %x\n", (UINT32)Status);
  }

  Status = SpdmStopSession (SpdmContext, SessionId, 0);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStopSession - %x\n", (UINT32)Status);
    return Status;
  }

  Status = SpdmStopSession (SpdmContext, SessionId2, 0);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStopSession - %x\n", (UINT32)Status);
    return Status;
  }

  return Status;
}