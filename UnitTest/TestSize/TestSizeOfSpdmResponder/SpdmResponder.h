/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_RESPONDER_H__
#define __SPDM_RESPONDER_H__

#include <Base.h>
#include <Library/SpdmResponderLib.h>
#include <Library/SpdmTransportMctpLib.h>
#include <Library/MemoryAllocationLib.h>

VOID *
SpdmServerInit (
  VOID
  );

#endif