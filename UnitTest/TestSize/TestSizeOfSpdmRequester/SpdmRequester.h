/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_REQUESTER_H__
#define __SPDM_REQUESTER_H__

#include <Base.h>
#include <Library/SpdmRequesterLib.h>
#include <Library/SpdmTransportMctpLib.h>
#include <Library/MemoryAllocationLib.h>

RETURN_STATUS
DoAuthenticationViaSpdm (
  IN VOID   *SpdmContext
  );

RETURN_STATUS
DoSessionViaSpdm (
  IN VOID   *SpdmContext
  );

VOID *
SpdmClientInit (
  VOID
  );

#endif