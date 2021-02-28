/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderEmu.h"

SPDM_VENDOR_DEFINED_RESPONSE_MINE  mVendorDefinedResponse = {
  {
    SPDM_MESSAGE_VERSION_10,
    SPDM_VENDOR_DEFINED_RESPONSE,
    0, // Param1
    0, // Param2
  },
  SPDM_REGISTRY_ID_PCISIG, // StandardID
  2, // Len
  SPDM_VENDOR_ID_PCISIG, // VendorID
  sizeof(PCI_PROTOCOL_HEADER) + sizeof(PCI_IDE_KM_QUERY_RESP), // PayloadLength
  {
    PCI_PROTOCAL_ID_IDE_KM,
  },
  {
    {
      PCI_IDE_KM_OBJECT_ID_QUERY_RESP,
    },
    0, // Reserved
    0, // PortIndex
    0, // DevFuncNum
    0, // BusNum
    0, // Segment
    7, // MaxPortIndex
  }
};

SECURE_SESSION_RESPONSE_MINE  mSecureSessionResponse = {
  {
    MCTP_MESSAGE_TYPE_PLDM
  },
  {
    0,
    PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,
    PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,
  },
  {
    PLDM_BASE_CODE_SUCCESS,
  },
  1, // TID
};

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
  SECURE_SESSION_REQUEST_MINE        *AppRequest;

  if (!IsAppMessage) {
    SpmdRequest = Request;
    ASSERT ((RequestSize >= sizeof(SPDM_VENDOR_DEFINED_REQUEST_MINE)) && (RequestSize < sizeof(SPDM_VENDOR_DEFINED_REQUEST_MINE) + 4));
    ASSERT (SpmdRequest->Header.RequestResponseCode == SPDM_VENDOR_DEFINED_REQUEST);
    ASSERT (SpmdRequest->StandardID == SPDM_REGISTRY_ID_PCISIG);
    ASSERT (SpmdRequest->VendorID == SPDM_VENDOR_ID_PCISIG);
    ASSERT (SpmdRequest->PayloadLength == sizeof(PCI_PROTOCOL_HEADER) + sizeof(PCI_IDE_KM_QUERY));
    ASSERT (SpmdRequest->PciProtocol.ProtocolId == PCI_PROTOCAL_ID_IDE_KM);
    ASSERT (SpmdRequest->PciIdeKmQuery.Header.ObjectId == PCI_IDE_KM_OBJECT_ID_QUERY);

    CopyMem (Response, &mVendorDefinedResponse, sizeof(mVendorDefinedResponse));
    *ResponseSize = sizeof(mVendorDefinedResponse);
  } else {
    AppRequest = Request;
    ASSERT (RequestSize == sizeof(SECURE_SESSION_REQUEST_MINE));
    ASSERT (AppRequest->MctpHeader.MessageType == MCTP_MESSAGE_TYPE_PLDM);
    ASSERT (AppRequest->PldmHeader.PldmType == PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY);
    ASSERT (AppRequest->PldmHeader.PldmCommandCode == PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID);

    CopyMem (Response, &mSecureSessionResponse, sizeof(mSecureSessionResponse));
    *ResponseSize = sizeof(mSecureSessionResponse);
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
