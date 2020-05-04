/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_LIB_CONFIG_H__
#define __SPDM_LIB_CONFIG_H__

#define DEFAULT_OPAQUE_LENGTH             16
#define DEFAULT_OPAQUE_DATA               0xCC
#define DEFAULT_CONTEXT_LENGTH            MAX_HASH_SIZE
#define DEFAULT_SECURE_MCTP_PADDING_SIZE  1

#define MAX_SPDM_MEASUREMENT_BLOCK_COUNT  8
#define MAX_SPDM_SESSION_COUNT            1
#define MAX_SPDM_CERT_CHAIN_SIZE          0x1000
#define MAX_SPDM_MEASUREMENT_RECORD_SIZE  0x1000
#define MAX_SPDM_CERT_CHAIN_BLOCK_LEN     1024

#define MAX_SPDM_MESSAGE_BUFFER_SIZE      0x1000
#define MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE 0x100

 // TBD remove me - DEFAULT_MANAGED_BUFFER_STEP_SIZE
#define DEFAULT_MANAGED_BUFFER_STEP_SIZE  1024

#endif