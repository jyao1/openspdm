/** @file
  SPDM MCTP Transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_MCTP_TRANSPORT_LIB_H__
#define __SPDM_MCTP_TRANSPORT_LIB_H__

#include <Library/SpdmCommonLib.h>

RETURN_STATUS
EFIAPI
SpdmMctpEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *MctpMessageSize,
     OUT VOID                 *MctpMessage
  );

RETURN_STATUS
EFIAPI
SpdmMctpDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
  IN     UINTN                MctpMessageSize,
  IN     VOID                 *MctpMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  );

#endif