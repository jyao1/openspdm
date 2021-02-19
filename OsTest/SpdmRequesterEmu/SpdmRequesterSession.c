/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

extern VOID          *mSpdmContext;

RETURN_STATUS
DoMeasurementViaSpdm (
  IN UINT32        *SessionId
  );

typedef struct {
  SPDM_DATA_TYPE        DataType;
  CHAR8                 *String;
} DATA_TYPE_STRING;

SPDM_VENDOR_DEFINED_REQUEST_MINE  mVendorDefinedRequest = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_REQUEST,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_PCISIG, // StandardID
  2, // Len
  SPDM_VENDOR_ID_PCISIG, // VendorID
  sizeof(PCI_PROTOCOL_HEADER) + sizeof(PCI_IDE_KM_QUERY), // PayloadLength
  {
    PCI_PROTOCAL_ID_IDE_KM,
  },
  {
    {
      PCI_IDE_KM_OBJECT_ID_QUERY,
    },
    0, // Reserved
    0, // PortIndex
  }
};

SECURE_SESSION_REQUEST_MINE  mSecureSessionRequest = {
  {
    MCTP_MESSAGE_TYPE_PLDM
  },
  {
    0x80,
    PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
    PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
  },
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
  SECURE_SESSION_RESPONSE_MINE       AppResponse;
  UINTN                              AppResponseSize;

  SpdmContext = mSpdmContext;

  CopyMem (&Request, &mVendorDefinedRequest, sizeof(Request));

  RequestSize = sizeof(Request);
  ResponseSize = sizeof(Response);
  Status = SpdmSendReceiveData (SpdmContext, &SessionId, FALSE, &Request, RequestSize, &Response, &ResponseSize);
  ASSERT_RETURN_ERROR(Status);

  ASSERT (ResponseSize == sizeof(SPDM_VENDOR_DEFINED_RESPONSE_MINE));
  ASSERT (Response.Header.RequestResponseCode == SPDM_VENDOR_DEFINED_RESPONSE);
  ASSERT (Response.StandardID == SPDM_REGISTRY_ID_PCISIG);
  ASSERT (Response.VendorID == SPDM_VENDOR_ID_PCISIG);
  ASSERT (Response.PayloadLength == sizeof(PCI_PROTOCOL_HEADER) + sizeof(PCI_IDE_KM_QUERY_RESP));
  ASSERT (Response.PciProtocol.ProtocolId == PCI_PROTOCAL_ID_IDE_KM);
  ASSERT (Response.PciIdeKmQueryResp.Header.ObjectId == PCI_IDE_KM_OBJECT_ID_QUERY_RESP);

  if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
    AppResponseSize = sizeof(AppResponse);
    Status = SpdmSendReceiveData (SpdmContext, &SessionId, TRUE, &mSecureSessionRequest, sizeof(mSecureSessionRequest), &AppResponse, &AppResponseSize);
    ASSERT_RETURN_ERROR(Status);

    ASSERT (AppResponseSize == sizeof(AppResponse));
    ASSERT (AppResponse.MctpHeader.MessageType == MCTP_MESSAGE_TYPE_PLDM);
    ASSERT (AppResponse.PldmHeader.PldmType == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
    ASSERT (AppResponse.PldmHeader.PldmCommandCode == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);
    ASSERT (AppResponse.PldmResponseHeader.PldmCompletionCode == PLDM_BASE_CODE_SUCCESS);
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
  UINT32                           SessionId;
  UINT32                           SessionId2;
  UINT8                            HeartbeatPeriod;
  UINT8                            MeasurementHash[MAX_HASH_SIZE];

  SpdmContext = mSpdmContext;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             FALSE, // KeyExchange
             mUseMeasurementSummaryHashType,
             mUseSlotId,
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
             mUseMeasurementSummaryHashType,
             mUseSlotId,
             &SessionId2,
             &HeartbeatPeriod,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStartSession - %x\n", (UINT32)Status);
    return Status;
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

  Status = DoMeasurementViaSpdm (&SessionId);
  if (RETURN_ERROR(Status)) {
    printf ("DoMeasurementViaSpdm - %x\n", (UINT32)Status);
  }

  Status = SpdmStopSession (SpdmContext, SessionId, mEndSessionAttributes);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStopSession - %x\n", (UINT32)Status);
    return Status;
  }

  Status = SpdmStopSession (SpdmContext, SessionId2, mEndSessionAttributes);
  if (RETURN_ERROR(Status)) {
    printf ("SpdmStopSession - %x\n", (UINT32)Status);
    return Status;
  }

  return Status;
}