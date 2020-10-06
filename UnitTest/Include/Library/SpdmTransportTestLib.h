/** @file
  SPDM Test Transport library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_TRANSPORT_LIB_H__
#define __SPDM_TEST_TRANSPORT_LIB_H__

#include <Library/SpdmCommonLib.h>

#define TEST_MESSAGE_TYPE_SPDM                0x01
#define TEST_MESSAGE_TYPE_SECURED_TEST        0x02

RETURN_STATUS
EFIAPI
SpdmTransportTestEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TransportMessageSize,
     OUT VOID                 *TransportMessage
  );

RETURN_STATUS
EFIAPI
SpdmTransportTestDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                TransportMessageSize,
  IN     VOID                 *TransportMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  );

#endif