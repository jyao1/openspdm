/** @file
  SPDM Secured Message library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURED_MESSAGE_LIB_INTERNAL_H__
#define __SPDM_SECURED_MESSAGE_LIB_INTERNAL_H__

#include <Library/SpdmSecuredMessageLib.h>

typedef struct {
  UINT8                DheSecret[MAX_DHE_KEY_SIZE];
  UINT8                HandshakeSecret[MAX_HASH_SIZE];
  UINT8                MasterSecret[MAX_HASH_SIZE];
} SPDM_SESSION_INFO_MASTER_SECRET;

typedef struct {
  UINT8                RequestHandshakeSecret[MAX_HASH_SIZE];
  UINT8                ResponseHandshakeSecret[MAX_HASH_SIZE];
  UINT8                ExportMasterSecret[MAX_HASH_SIZE];
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  UINT8                ResponseFinishedKey[MAX_HASH_SIZE];
  UINT8                RequestHandshakeEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                RequestHandshakeSalt[MAX_AEAD_IV_SIZE];
  UINT64               RequestHandshakeSequenceNumber;
  UINT8                ResponseHandshakeEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                ResponseHandshakeSalt[MAX_AEAD_IV_SIZE];
  UINT64               ResponseHandshakeSequenceNumber;
} SPDM_SESSION_INFO_HANDSHAKE_SECRET;

typedef struct {
  UINT8                RequestDataSecret[MAX_HASH_SIZE];
  UINT8                ResponseDataSecret[MAX_HASH_SIZE];
  UINT8                RequestDataEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                RequestDataSalt[MAX_AEAD_IV_SIZE];
  UINT64               RequestDataSequenceNumber;
  UINT8                ResponseDataEncryptionKey[MAX_AEAD_KEY_SIZE];
  UINT8                ResponseDataSalt[MAX_AEAD_IV_SIZE];
  UINT64               ResponseDataSequenceNumber;
} SPDM_SESSION_INFO_APPLICATION_SECRET;

typedef struct {
  SPDM_SESSION_TYPE                    SessionType;
  UINT32                               BaseHashAlgo;
  UINT16                               DHENamedGroup;
  UINT16                               AEADCipherSuite;
  UINT16                               KeySchedule;
  UINTN                                HashSize;
  UINTN                                DheKeySize;
  UINTN                                AeadKeySize;
  UINTN                                AeadIvSize;
  UINTN                                AeadBlockSize;
  UINTN                                AeadTagSize;
  BOOLEAN                              UsePsk;
  SPDM_SESSION_STATE                   SessionState;
  SPDM_SESSION_INFO_MASTER_SECRET      MasterSecret;
  SPDM_SESSION_INFO_HANDSHAKE_SECRET   HandshakeSecret;
  SPDM_SESSION_INFO_APPLICATION_SECRET ApplicationSecret;
  SPDM_SESSION_INFO_APPLICATION_SECRET ApplicationSecretBackup;
  UINTN                                PskHintSize;
  VOID                                 *PskHint;
  //
  // Cache the error in SpdmDecodeSecuredMessage. It is handled in SpdmBuildResponse.
  //
  SPDM_ERROR_STRUCT                    LastSpdmError;
} SPDM_SECURED_MESSAGE_CONTEXT;

#endif