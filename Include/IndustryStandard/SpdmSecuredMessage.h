/** @file
  Definitions of DSP0277 Secured Messages using SPDM Specification
  version 1.0.0 in Distributed Management Task Force (DMTF).

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURED_MESSAGE_H__
#define __SPDM_SECURED_MESSAGE_H__

#pragma pack(1)

//
// ENC+AUTH session:
//
// +-----------------+
// | ApplicationData |-----------------------------------------------------
// +-----------------+                                                     |
//                                                                         V
// +---------------------------------+--------------------------=-------+-------+------+---+
// |SPDM_SECURED_MESSAGE_ADATA_HEADER|SPDM_SECURED_MESSAGE_CIPHER_HEADER|AppData|Random|MAC|
// | SessionId | SeqNum (O) | Length |       ApplicationDataLength      |       |  (O) |   |
// +---------------------------------+----------------------------------+-------+------+---+
// |                                 |                                                 |   |
//  --------------------------------- ------------------------------------------------- ---
//                  |                                         |                          |
//                  V                                         V                          V
//            AssociatedData                            EncryptedData                 AeadTag
//
// (O) means Optional or Transport Layer Specific.
//
// AUTH session:
//
// +-----------------+
// | ApplicationData |------------------
// +-----------------+                  |
//                                      V
// +---------------------------------+-------+---+
// |SPDM_SECURED_MESSAGE_ADATA_HEADER|AppData|MAC|
// | SessionId | SeqNum (T) | Length |       |   |
// +---------------------------------+-------+---+
// |                                         |   |
//  ----------------------------------------- ---
//                      |                     |
//                      V                     V
//                AssociatedData           AeadTag
//

typedef struct {
  UINT32   SessionId;
} SPDM_SECURED_MESSAGE_ADATA_HEADER_1;

// The length of SequenceNumber between HEADER_1 and HEADER_2 is transport specific.

typedef struct {
  UINT16   Length; // The length of the remaining data, including ApplicationDataLength(O), Payload, Random(O) and MAC.
} SPDM_SECURED_MESSAGE_ADATA_HEADER_2;

typedef struct {
  UINT16   ApplicationDataLength; // The length of the Payload
} SPDM_SECURED_MESSAGE_CIPHER_HEADER;

//
// Secured Messages opaque data format
//
#define SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID  0x444D5446
#define SECURED_MESSAGE_OPAQUE_VERSION       0x1

typedef struct {
  UINT32   SpecId;        // SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID
  UINT8    OpaqueVersion; // SECURED_MESSAGE_OPAQUE_VERSION
  UINT8    TotalElements;
  UINT16   Reserved;
//OPAQUE_ELEMENT_TABLE  OpaqueList[];
} SECURED_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER;

typedef struct {
  UINT8    Id;
  UINT8    VendorLen;
//UINT8    VendorID[VendorLen];
//UINT16   OpaqueElementDataLen;
//UINT8    OpaqueElementData[OpaqueElementDataLen];
//UINT8    AlignPadding[];
} OPAQUE_ELEMENT_TABLE_HEADER;

#define SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION  0x1

typedef struct {
  UINT8    Id; // SPDM_REGISTRY_ID_DMTF
  UINT8    VendorLen;
  UINT16   OpaqueElementDataLen;
//UINT8    SMDataVersion;
//UINT8    SMDataID;
//UINT8    SMDatap[];
} SECURED_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER;

typedef struct {
  UINT8                 SMDataVersion; // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION
  UINT8                 SMDataID;      // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION
} SECURED_MESSAGE_OPAQUE_ELEMENT_HEADER;

#define SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION  0x0

typedef struct {
  UINT8                 SMDataVersion; // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION
  UINT8                 SMDataID;      // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION
  SPDM_VERSION_NUMBER   SelectedVersion;
} SECURED_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION;

#define SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION  0x1

typedef struct {
  UINT8                 SMDataVersion; // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION
  UINT8                 SMDataID;      // SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION
  UINT8                 VersionCount;
//SPDM_VERSION_NUMBER   VersionsList[VersionCount];
} SECURED_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION;

#pragma pack()

#endif
