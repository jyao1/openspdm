/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterTest.h"

extern VOID          *mSpdmContext;

typedef struct {
  SPDM_DATA_TYPE  DataType;
  CHAR8           *String;
} DATA_TYPE_STRING;

DATA_TYPE_STRING  mDataTypeString[] = {
  {SpdmDataDheSecret,        "DheSecret"},
  {SpdmDataHandshakeSecret,  "HandshakeSecret"},
  {SpdmDataMasterSecret,     "MasterSecret"},
  {SpdmDataRequestHandshakeSecret,   "RequestHandshakeSecret"},
  {SpdmDataResponseHandshakeSecret,  "ResponseHandshakeSecret"},
  {SpdmDataRequestDataSecret,        "RequestDataSecret"},
  {SpdmDataResponseDataSecret,       "ResponseDataSecret"},
  {SpdmDataRequestFinishedKey,       "RequestFinishedKey"},
  {SpdmDataResponseFinishedKey,      "ResponseFinishedKey"},
  {SpdmDataRequestHandshakeEncryptionKey,  "RequestHandshakeEncryptionKey"},
  {SpdmDataRequestHandshakeSalt,           "RequestHandshakeSalt"},
  {SpdmDataResponseHandshakeEncryptionKey, "ResponseHandshakeEncryptionKey"},
  {SpdmDataResponseHandshakeSalt,          "ResponseHandshakeSalt"},
  {SpdmDataRequestDataEncryptionKey,       "RequestDataEncryptionKey"},
  {SpdmDataRequestDataSalt,                "RequestDataSalt"},
  {SpdmDataResponseDataEncryptionKey,      "ResponseDataEncryptionKey"},
  {SpdmDataResponseDataSalt,               "ResponseDataSalt"},
};

SPDM_VENDOR_DEFINED_REQUEST_MINE  mVendorDefinedRequest = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_REQUEST,
    0, // Param1
    0, // Param2
  },
  SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_PCISIG, // StandardID
  2, // Len
  0x8086, // VendorID
  TEST_PAYLOAD_LEN, // PayloadLength
  {TEST_PAYLOAD_CLIENT}
};

RETURN_STATUS
DoAppSessionViaSpdm (
  IN UINT8                           SessionId
  )
{
  VOID                               *SpdmContext;
  RETURN_STATUS                      Status;
  SPDM_VENDOR_DEFINED_REQUEST_MINE   Request;
  UINTN                              RequestSize;
  SPDM_VENDOR_DEFINED_RESPONSE_MINE  Response;
  UINTN                              ResponseSize;

  SpdmContext = mSpdmContext;

  CopyMem (&Request, &mVendorDefinedRequest, sizeof(Request));

  RequestSize = sizeof(Request);
  ResponseSize = sizeof(Response);
  Status = SpdmSendReceiveSessionData (SpdmContext, SessionId, &Request, RequestSize, &Response, &ResponseSize);
  if (RETURN_ERROR(Status)) {
    return Status;
  }

  ASSERT (ResponseSize == sizeof(SPDM_VENDOR_DEFINED_RESPONSE_MINE));
  ASSERT (Response.Header.RequestResponseCode == SPDM_VENDOR_DEFINED_RESPONSE);
  ASSERT (Response.StandardID == SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_PCISIG);
  ASSERT (Response.VendorID == 0x8086);
  ASSERT (Response.PayloadLength == TEST_PAYLOAD_LEN);
  ASSERT (CompareMem (Response.VendorDefinedPayload, TEST_PAYLOAD_SERVER, TEST_PAYLOAD_LEN) == 0);

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
  UINT8                            SessionId;
  SPDM_DATA_PARAMETER              Parameter;
  UINT8                            HeartbeatPeriod;
  UINT8                            MeasurementHash[MAX_HASH_SIZE];

  SpdmContext = mSpdmContext;

#if USE_PSK
  Status = SpdmSetData (SpdmContext, SpdmDataPsk, NULL, "TestPskData", sizeof("TestPskData"));
  if (RETURN_ERROR(Status)) {
    printf ("SpdmSetData - %x\n", (UINT32)Status);
    return Status;
  }
#endif

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             USE_PSK,
             SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
             0,
             &HeartbeatPeriod,
             &SessionId,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStartSession - %x\n", (UINT32)Status);
    return Status;
  }
  
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  Parameter.AdditionalData[0] = SessionId;
  for (Index = 0; Index < ARRAY_SIZE(mDataTypeString); Index++) {
    DataSize = sizeof(Data);
    ZeroMem (Data, sizeof(Data));
    Status = SpdmGetData (SpdmContext, mDataTypeString[Index].DataType, &Parameter, Data, &DataSize);
    if (!RETURN_ERROR(Status)) {
      printf ("%s (%d) - ", mDataTypeString[Index].String, (UINT32)DataSize);
      DumpData (Data, DataSize);
    } else {
      printf ("%s - %x\n", mDataTypeString[Index].String, (UINT32)Status);
    }
  }

  DoAppSessionViaSpdm (SessionId);

  Status = SpdmStopSession (SpdmContext, SessionId, 0);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStopSession - %x\n", (UINT32)Status);
    return Status;
  }

  return Status;
}