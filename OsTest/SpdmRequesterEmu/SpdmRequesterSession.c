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

  if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
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
  }

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
  IN     BOOLEAN              UsePsk
  )
{
  VOID                             *SpdmContext;
  RETURN_STATUS                    Status;
  UINT32                           SessionId;
  UINT8                            HeartbeatPeriod;
  UINT8                            MeasurementHash[MAX_HASH_SIZE];

  SpdmContext = mSpdmContext;

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             UsePsk,
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

  DoAppSessionViaSpdm (SessionId);

  if ((mExeSession & EXE_SESSION_HEARTBEAT) != 0) {
    Status = SpdmHeartbeat (SpdmContext, SessionId);
    if (RETURN_ERROR(Status)) {
      printf ("SpdmHeartbeat - %x\n", (UINT32)Status);
    }
  }

  if ((mExeSession & EXE_SESSION_KEY_UPDATE) != 0) {
    Status = SpdmKeyUpdate (SpdmContext, SessionId, TRUE);
    if (RETURN_ERROR(Status)) {
      printf ("SpdmKeyUpdate - %x\n", (UINT32)Status);
    }
  }

  if ((mExeSession & EXE_SESSION_MEAS) != 0) {
    Status = DoMeasurementViaSpdm (&SessionId);
    if (RETURN_ERROR(Status)) {
      printf ("DoMeasurementViaSpdm - %x\n", (UINT32)Status);
    }
  }

  if ((mExeSession & EXE_SESSION_NO_END) == 0) {
    Status = SpdmStopSession (SpdmContext, SessionId, mEndSessionAttributes);
    if (RETURN_ERROR(Status)) {
      printf ("SpdmStopSession - %x\n", (UINT32)Status);
      return Status;
    }
  }

  return Status;
}