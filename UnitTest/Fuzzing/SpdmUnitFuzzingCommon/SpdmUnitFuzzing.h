/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_UNIT_TEST_H__
#define __SPDM_UNIT_TEST_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmResponderLib.h>
#include <Library/SpdmTransportTestLib.h>
#include <SpdmCommonLibInternal.h>

#define SPDM_TEST_CONTEXT_SIGNATURE  SIGNATURE_32 ('S', 'T', 'C', 'S')

typedef struct {
  UINT32                            Signature;
  BOOLEAN                           IsRequester;
  SPDM_DEVICE_SEND_MESSAGE_FUNC     SendMessage;
  SPDM_DEVICE_RECEIVE_MESSAGE_FUNC  ReceiveMessage;
  VOID                              *SpdmContext;
  VOID                              *TestBuffer;
  UINTN                             TestBufferSize;
} SPDM_TEST_CONTEXT;

#define SPDM_TEST_CONTEXT_FROM_SPDM_PROTOCOL(a)  BASE_CR (a, SPDM_TEST_CONTEXT, SpdmProtocol)
#define SPDM_TEST_CONTEXT_FROM_SPDM_CONTEXT(a)   BASE_CR (a, SPDM_TEST_CONTEXT, SpdmContext)

UINTN SpdmUnitTestGroupSetup(VOID **State);

UINTN SpdmUnitTestGroupTeardown(VOID **State);

VOID
SetupSpdmTestContext (
  IN SPDM_TEST_CONTEXT       *SpdmTestContext
  );

SPDM_TEST_CONTEXT *
GetSpdmTestContext (
  VOID
  );

#endif