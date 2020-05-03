/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_COMMON_LIB_H__
#define __SPDM_COMMON_LIB_H__

#include "SpdmLibConfig.h"

#include <Base.h>
#include <IndustryStandard/Spdm.h>
#include <IndustryStandard/SpdmMctp.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseCryptLib.h>
#include <Protocol/SpdmIo.h>
#include <Protocol/Spdm.h>

//
// Connection: When a host sends messgages to a device, they create a connection.
//             The host can and only can create one connection with one device.
//             The host may create multiple connections with multiple devices at same time.
//             A connection can be unique identified by the connected device.
//             The message exchange in a connection is plain text.
//
// Session: In one connection with one device, a host may create multiple sessions.
//          The session starts with via KEY_EXCHANGE or PSK_EXCHANGE, and step with END_SESSION.
//          A session can be unique identified by a session ID, returned from the device.
//          The message exchange in a session is cipher text.
//

#define MAX_SPDM_VERSION_COUNT            2
#define MAX_SPDM_SLOT_COUNT               8
#define MAX_SPDM_OPAQUE_DATA_SIZE         1024

#define SPDM_NONCE_SIZE           32
#define SPDM_RANDOM_DATA_SIZE     32

#define MAX_DHE_KEY_SIZE    512
#define MAX_ASYM_KEY_SIZE   512
#define MAX_HASH_SIZE       64
#define MAX_AEAD_KEY_SIZE   32
#define MAX_AEAD_IV_SIZE    12

#define EDKII_SPDM_ERROR_STATUS_SUCCESS                          0
#define EDKII_SPDM_ERROR_STATUS_ERROR                            BIT31
#define EDKII_SPDM_ERROR_STATUS_ERROR_DEVICE_NO_CAPABILITIES     (EDKII_SPDM_ERROR_STATUS_ERROR + 0x10)
#define EDKII_SPDM_ERROR_STATUS_ERROR_DEVICE_ERROR               (EDKII_SPDM_ERROR_STATUS_ERROR + 0x11)
#define EDKII_SPDM_ERROR_STATUS_ERROR_TCG_EXTEND_TPM_PCR         (EDKII_SPDM_ERROR_STATUS_ERROR + 0x20)
#define EDKII_SPDM_ERROR_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE   (EDKII_SPDM_ERROR_STATUS_ERROR + 0x21)
#define EDKII_SPDM_ERROR_STATUS_ERROR_CHALLENGE_FAILURE          (EDKII_SPDM_ERROR_STATUS_ERROR + 0x30)
#define EDKII_SPDM_ERROR_STATUS_ERROR_CERTIFIACTE_FAILURE        (EDKII_SPDM_ERROR_STATUS_ERROR + 0x31)
#define EDKII_SPDM_ERROR_STATUS_ERROR_NO_CERT_PROVISION          (EDKII_SPDM_ERROR_STATUS_ERROR + 0x32)
#define EDKII_SPDM_ERROR_STATUS_ERROR_KEY_EXCHANGE_FAILURE       (EDKII_SPDM_ERROR_STATUS_ERROR + 0x40)
#define EDKII_SPDM_ERROR_STATUS_ERROR_NO_MUTUAL_AUTH             (EDKII_SPDM_ERROR_STATUS_ERROR + 0x41)

/**
  Set a SPDM Session Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The Data is NULL or the DataType is zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_ACCESS_DENIED            The DataType cannot be set.
  @retval RETURN_NOT_READY                Current session is not started.
**/
RETURN_STATUS
EFIAPI
SpdmSetData (
  IN     VOID                     *SpdmContext,
  IN     EDKII_SPDM_DATA_TYPE      DataType,
  IN     EDKII_SPDM_DATA_PARAMETER *Parameter,
  IN     VOID                      *Data,
  IN     UINTN                     DataSize
  );

/**
  Get a SPDM Session Data.

  @param  This                         Indicates a pointer to the calling context.
  @param  DataType                     Type of the session data.
  @param  Data                         A pointer to the session data.
  @param  DataSize                     Size of the session data. On input, it means the size of Data
                                       buffer. On output, it means the size of copied Data buffer if
                                       RETURN_SUCCESS, and means the size of desired Data buffer if
                                       RETURN_BUFFER_TOO_SMALL.

  @retval RETURN_SUCCESS                  The SPDM session data is set successfully.
  @retval RETURN_INVALID_PARAMETER        The DataSize is NULL or the Data is NULL and *DataSize is not zero.
  @retval RETURN_UNSUPPORTED              The DataType is unsupported.
  @retval RETURN_NOT_FOUND                The DataType cannot be found.
  @retval RETURN_NOT_READY                The DataType is not ready to return.
  @retval RETURN_BUFFER_TOO_SMALL         The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmGetData (
  IN     VOID                      *SpdmContext,
  IN     EDKII_SPDM_DATA_TYPE      DataType,
  IN     EDKII_SPDM_DATA_PARAMETER *Parameter,
  IN OUT VOID                      *Data,
  IN OUT UINTN                     *DataSize
  );

UINT32
EFIAPI
SpdmGetLastError (
  IN     VOID                      *SpdmContext
  );

RETURN_STATUS
EFIAPI
SpdmInitContext (
  IN     VOID                      *SpdmContext
  );

UINTN
EFIAPI
SpdmGetContextSize (
  VOID
  );

#endif