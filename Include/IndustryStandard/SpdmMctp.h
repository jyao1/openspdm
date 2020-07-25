/** @file
  SPDM Session Record definition

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_MCTP_DEFINITION_H__
#define __SPDM_MCTP_DEFINITION_H__

//
// +---------+
// | Payload |------------------------------------------------------------------------------------
// +---------+                                                                                    |
//                                                                                                V
// +--------------------+-----------------------------+---------------------------------------+-------+---+
// |MCTP_MESSAGE_TYPE(6)|MCTP_MESSAGE_PLAINTEXT_HEADER|    MCTP_MESSAGE_CIPHERTEXT_HEADER     |Payload|MAC|
// |                    |  SessionId  |    Length     |TrueLength|Padding|MCTP_MESSAGE_TYPE(5)|       |   |
// +--------------------+-----------------------------+---------------------------------------+-------+---+
//                      |                             |                                               |   |
//                       ----------------------------- ---------------------------------------------- ---
//                                    |                                        |                        |
//                                    V                                        V                        V
//                               AssociatedData                          EncryptedData               AeadTag
//

#pragma pack(1)

#define MCTP_MESSAGE_TYPE_SPDM            5
#define MCTP_MESSAGE_TYPE_SECURE_MESSAGE  6

typedef struct {
  UINT8    MessageType:7;
  UINT8    IntegrityCheck:1;
} MCTP_MESSAGE_TYPE;

typedef struct {
  UINT32   SessionId;
  UINT16   Length; // This field shall be the remaining length of data in the MCTP message.
} MCTP_MESSAGE_PLAINTEXT_HEADER;

typedef struct {
  UINT16               TrueLength; // This field shall be the remaining length of data minus the padding length
  UINT8                Padding[1]; // 1~32 bytes
  MCTP_MESSAGE_TYPE    EncapsulatedMessageType;
} MCTP_MESSAGE_CIPHERTEXT_HEADER;

#pragma pack()

#endif
