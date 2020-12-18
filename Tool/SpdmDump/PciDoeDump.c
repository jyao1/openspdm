/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPciDoePacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_DOE_DATA_OBJECT_HEADER  *PciDoeHeader;
  UINTN                HeaderSize;

  HeaderSize = sizeof(PCI_DOE_DATA_OBJECT_HEADER);
  if (BufferSize < HeaderSize) {
    return ;
  }
  PciDoeHeader = Buffer;

  printf ("PCI_DOE(%d, %d) ", PciDoeHeader->VendorId, PciDoeHeader->DataObjectType);

  if (PciDoeHeader->VendorId != PCI_DOE_VENDOR_ID_PCISIG) {
    return ;
  }
  switch (PciDoeHeader->DataObjectType) {
  case PCI_DOE_DATA_OBJECT_TYPE_SPDM:
    DumpSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
    break;
  case PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM:
    DumpSecuredSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
    break;
  case PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY:
    // TBD
  default:
    printf ("\n");
    break;
  }
}
