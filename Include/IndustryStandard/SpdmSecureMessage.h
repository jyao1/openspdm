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
// |  SessionId  |    Length        |           TrueLength (O)        |       |  (O) |   |
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
  UINT16   Length; // The length of the remaining data, including TrueLength(O), Payload, Random(O) and MAC.
} SPDM_SECURE_MESSAGE_ADATA_HEADER;

typedef struct {
  UINT16   TrueLength; // The length of the Payload
} SPDM_SECURE_MESSAGE_CIPHER_HEADER;

#pragma pack()

#endif
