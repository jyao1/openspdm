/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPciIdeKmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("PCI_IDE_KM\n");
}
