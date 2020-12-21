/** @file
  Definitions of Component Measurement and Authentication (CMA) ECN in PCI-SIG.

  Definitions of Data Object Exchange (DOE) ECN in PCI-SIG.

  Definitions of Integrity and Data Encryption (IDE) ECN in PCI-SIG.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PCI_DOE_BINDING_H__
#define __PCI_DOE_BINDING_H__

#pragma pack(1)

//
// DOE header
//
typedef struct {
  UINT16   VendorId;
  UINT8    DataObjectType;
  UINT8    Reserved;
  // Length of the data object being transfered in number of DW, including the header (2 DW)
  // It only includes bit[0~17], bit[18~31] are reserved.
  // A value of 00000h indicate 2^18 DW == 2^20 byte.
  UINT32   Length;
//UINT32   DataObjectDW[Length];
} PCI_DOE_DATA_OBJECT_HEADER;

#define PCI_DOE_VENDOR_ID_PCISIG                   0x0001

#define PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY     0x00
#define PCI_DOE_DATA_OBJECT_TYPE_SPDM              0x01
#define PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM      0x02

#define PCI_DOE_MAX_SIZE_IN_BYTE                   0x00100000
#define PCI_DOE_MAX_SIZE_IN_DW                     0x00040000

//
// DOE Discovery
//
typedef struct {
  UINT8  Index;
  UINT8  Reserved[3];
} PCI_DOE_DISCOVERY_REQUEST;

typedef struct {
  UINT16 VendorId;
  UINT8  DataObjectType;
  UINT8  NextIndex;
} PCI_DOE_DISCOVERY_RESPONSE;


#pragma pack()

#endif
