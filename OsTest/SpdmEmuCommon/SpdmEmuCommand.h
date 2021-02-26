/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_COMMAND_H__
#define __SPDM_TEST_COMMAND_H__

#define DEFAULT_SPDM_PLATFORM_PORT 2323

//
// Client->Server/Server->Client
//   Command/Response: 4 bytes (big endian)
//   TransportType: 4 bytes (big endian)
//   PayloadSize (excluding Command and PayloadSize): 4 bytes (big endian)
//   Payload (SPDM message, starting from SPDM_HEADER): PayloadSize (little endian)
//

#define SOCKET_TRANSPORT_TYPE_MCTP     0x01
#define SOCKET_TRANSPORT_TYPE_PCI_DOE  0x02

#define SOCKET_SPDM_COMMAND_NORMAL                0x0001
#define SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE  0x8001
#define SOCKET_SPDM_COMMAND_CONTINUE              0xFFFD
#define SOCKET_SPDM_COMMAND_SHUTDOWN              0xFFFE
#define SOCKET_SPDM_COMMAND_UNKOWN                0xFFFF
#define SOCKET_SPDM_COMMAND_TEST                  0xDEAD

//
// Vendor Message
//
#pragma pack(1)

///
/// SPDM VENDOR_DEFINED request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT16               StandardID;
  UINT8                Len;
  UINT16               VendorID;
  UINT16               PayloadLength;
  PCI_PROTOCOL_HEADER  PciProtocol;
  PCI_IDE_KM_QUERY     PciIdeKmQuery;
} SPDM_VENDOR_DEFINED_REQUEST_MINE;

///
/// SPDM VENDOR_DEFINED response
///
typedef struct {
  SPDM_MESSAGE_HEADER    Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT16                 StandardID;
  UINT8                  Len;
  UINT16                 VendorID;
  UINT16                 PayloadLength;
  PCI_PROTOCOL_HEADER    PciProtocol;
  PCI_IDE_KM_QUERY_RESP  PciIdeKmQueryResp;
} SPDM_VENDOR_DEFINED_RESPONSE_MINE;

///
/// Secure Session APP request
///
typedef struct {
  MCTP_MESSAGE_HEADER  MctpHeader;
  PLDM_MESSAGE_HEADER  PldmHeader;
} SECURE_SESSION_REQUEST_MINE;

///
/// Secure Session APP response
///
typedef struct {
  MCTP_MESSAGE_HEADER          MctpHeader;
  PLDM_MESSAGE_HEADER          PldmHeader;
  PLDM_MESSAGE_RESPONSE_HEADER PldmResponseHeader;
  UINT8                        TID;
} SECURE_SESSION_RESPONSE_MINE;

///
/// DOE Discovery request
///
typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER  DoeHeader;
  PCI_DOE_DISCOVERY_REQUEST   DoeDiscoveryRequest;
} DOE_DISCOVERY_REQUEST_MINE;

///
/// DOE Discovery response
///
typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER  DoeHeader;
  PCI_DOE_DISCOVERY_RESPONSE  DoeDiscoveryResponse;
} DOE_DISCOVERY_RESPONSE_MINE;

#pragma pack()

#endif