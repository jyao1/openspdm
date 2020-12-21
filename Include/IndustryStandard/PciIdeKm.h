/** @file
  Definitions of Integrity and Data Encryption (IDE) ECN in PCI-SIG.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PCI_IDE_KM_H__
#define __PCI_IDE_KM_H__

//
// Standard ID and Vendor ID for PCISIG
//
#define SPDM_STANDARD_ID_PCISIG       SPDM_REGISTRY_ID_PCISIG
#define SPDM_VENDOR_ID_PCISIG         0x0001

#pragma pack(1)

//
// PCI Protocol definition
//
typedef struct {
  UINT8    ProtocolId;
} PCI_PROTOCOL_HEADER;

//
// IDE_KM Definition
//
#define PCI_PROTOCAL_ID_IDE_KM                     0x00

//
// IDE_KM header
//
typedef struct {
  UINT8    ObjectId;
} PCI_IDE_KM_HEADER;

#define PCI_IDE_KM_OBJECT_ID_QUERY                 0x00
#define PCI_IDE_KM_OBJECT_ID_QUERY_RESP            0x01
#define PCI_IDE_KM_OBJECT_ID_KEY_PROG              0x02
#define PCI_IDE_KM_OBJECT_ID_KP_ACK                0x03
#define PCI_IDE_KM_OBJECT_ID_K_SET_GO              0x04
#define PCI_IDE_KM_OBJECT_ID_K_SET_STOP            0x05
#define PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK      0x06

//
// IDE_KM QUERY
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved;
  UINT8              PortIndex;
} PCI_IDE_KM_QUERY;

//
// IDE_KM QUERY_RESP
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved;
  UINT8              PortIndex;
  UINT8              DevFuncNum;
  UINT8              BusNum;
  UINT8              Segment;
  UINT8              MaxPortIndex;
//IDE Extended Capability
} PCI_IDE_KM_QUERY_RESP;

//
// IDE_KM KEY_PROG
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved[2];
  UINT8              StreamId;
  UINT8              Reserved2;
  UINT8              KeySubStream;
  UINT8              PortIndex;
//KEY 8 DW 
//IFV(invocation field of the IV) 2 DW 
} PCI_IDE_KM_KEY_PROG;

//
// IDE_KM KP_ACK
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved[2];
  UINT8              StreamId;
  UINT8              Reserved2;
  UINT8              KeySubStream;
  UINT8              PortIndex;
} PCI_IDE_KM_KP_ACK;

//
// IDE_KM K_SET_GO
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved[2];
  UINT8              StreamId;
  UINT8              Reserved2;
  UINT8              KeySubStream;
  UINT8              PortIndex;
} PCI_IDE_KM_K_SET_GO;

//
// IDE_KM K_SET_STOP
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved[2];
  UINT8              StreamId;
  UINT8              Reserved2;
  UINT8              KeySubStream;
  UINT8              PortIndex;
} PCI_IDE_KM_K_SET_STOP;

//
// IDE_KM K_GOSTOP_ACK
//
typedef struct {
  PCI_IDE_KM_HEADER  Header;
  UINT8              Reserved[2];
  UINT8              StreamId;
  UINT8              Reserved2;
  UINT8              KeySubStream;
  UINT8              PortIndex;
} PCI_IDE_KM_K_GOSTOP_ACK;

#pragma pack()

#endif
