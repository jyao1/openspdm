/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPciDoeDiscoveryMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("DOE_DISCOVERY\n");
}
