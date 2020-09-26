/** @file
  SPDM Session Record definition

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURE_MESSAGE_H__
#define __SPDM_SECURE_MESSAGE_H__

#pragma pack(1)

//
// ENC+AUTH session:
//
// +---------+
// | Payload |------------------------------------------------------------
// +---------+                                                            |
//                                                                        V
// +--------------------------------+---------------------------------+-------+------+---+
// |SPDM_SECURE_MESSAGE_ADATA_HEADER|SPDM_SECURE_MESSAGE_CIPHER_HEADER|Payload|Random|MAC|
// |  SessionId  |    Length        |    ApplicationDataLength (O)    |       |  (O) |   |
// +--------------------------------+---------------------------------+-------+------+---+
// |                                |                                                |   |
//  -------------------------------- ------------------------------------------------ ---
//               |                                           |                         |
//               V                                           V                         V
//          AssociatedData                             EncryptedData                AeadTag
//

//
// AUTH session:
//
// +---------+
// | Payload |--------------------------
// +---------+                          |
//                                      V
// +--------------------------------+-------+---+
// |SPDM_SECURE_MESSAGE_ADATA_HEADER|Payload|MAC|
// |  SessionId  |    Length        |       |   |
// +--------------------------------+-------+---+
// |                                        |   |
//  ---------------------------------------- ---
//               |                            |
//               V                            V
//          AssociatedData                 AeadTag
//

typedef struct {
  UINT32   SessionId;
  UINT16   Length; // The length of the remaining data, including ApplicationDataLength(O), Payload, Random(O) and MAC.
} SPDM_SECURE_MESSAGE_ADATA_HEADER;

typedef struct {
  UINT16   ApplicationDataLength; // The length of the Payload
} SPDM_SECURE_MESSAGE_CIPHER_HEADER;

//
// Secured Messages opaque data format
//
#define SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID  0x444D546
#define SECURE_MESSAGE_OPAQUE_VERSION       0x1

typedef struct {
  UINT32   SpecId;        // SECURE_MESSAGE_OPAQUE_DATA_SPEC_ID
  UINT8    OpaqueVersion; // SECURE_MESSAGE_OPAQUE_VERSION
  UINT8    TotalElements;
  UINT16   Reserved;
//OPAQUE_ELEMENT_TABLE  OpaqueList[];
} SECURE_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER;

typedef struct {
  UINT8    Id;
  UINT8    VendorLen;
//UINT8    VendorID[VendorLen];
//UINT16   OpaqueElementDataLen;
//UINT8    OpaqueElementData[OpaqueElementDataLen];
//UINT8    AlignPadding[];
} OPAQUE_ELEMENT_TABLE_HEADER;

#define SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION  0x1

typedef struct {
  UINT8    Id; // SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF
  UINT8    VendorLen;
  UINT16   OpaqueElementDataLen;
//UINT8    SMDataVersion;
//UINT8    SMDataID;
//UINT8    SMDatap[];
} SECURE_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER;

#define SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION  0x0

typedef struct {
  UINT8                 SMDataVersion; // SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION
  UINT8                 SMDataID;      // SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION
  SPDM_VERSION_NUMBER   SelectedVersion;
} SECURE_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION;

#define SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION  0x1

typedef struct {
  UINT8                 SMDataVersion; // SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION
  UINT8                 SMDataID;      // SECURE_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION
  UINT8                 VersionCount;
//SPDM_VERSION_NUMBER   VersionsList[VersionCount];
} SECURE_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION;

#pragma pack()

#endif
