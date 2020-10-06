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
SpdmTestEncodeMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               *SessionId,
  IN     UINTN                SpdmMessageSize,
  IN     VOID                 *SpdmMessage,
  IN OUT UINTN                *TestMessageSize,
     OUT VOID                 *TestMessage
  );

RETURN_STATUS
EFIAPI
SpdmTestDecodeMessage (
  IN     VOID                 *SpdmContext,
     OUT UINT32               **SessionId,
  IN     UINTN                TestMessageSize,
  IN     VOID                 *TestMessage,
  IN OUT UINTN                *SpdmMessageSize,
     OUT VOID                 *SpdmMessage
  );

#endif