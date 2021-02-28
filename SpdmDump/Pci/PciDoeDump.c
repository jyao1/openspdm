/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

DISPATCH_TABLE_ENTRY mPciDoeDispatch[] = {
  {PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, "DoeDiscovery",  DumpPciDoeDiscoveryMessage},
  {PCI_DOE_DATA_OBJECT_TYPE_SPDM,          "SPDM",          DumpSpdmMessage},
  {PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM,  "SecuredSPDM",   DumpSecuredSpdmMessage},
};

VOID
DumpPciDoePacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_DOE_DATA_OBJECT_HEADER  *PciDoeHeader;
  UINTN                       HeaderSize;

  HeaderSize = sizeof(PCI_DOE_DATA_OBJECT_HEADER);
  if (BufferSize < HeaderSize) {
    printf ("\n");
    return ;
  }
  PciDoeHeader = Buffer;

  printf ("PCI_DOE(%d, %d) ", PciDoeHeader->VendorId, PciDoeHeader->DataObjectType);

  if (PciDoeHeader->VendorId != PCI_DOE_VENDOR_ID_PCISIG) {
    printf ("\n");
    return ;
  }
  
  if (mParamDumpVendorApp ||
      (PciDoeHeader->DataObjectType == PCI_DOE_DATA_OBJECT_TYPE_SPDM) ||
      (PciDoeHeader->DataObjectType == PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM)) {
    DumpDispatchMessage (mPciDoeDispatch, ARRAY_SIZE(mPciDoeDispatch), PciDoeHeader->DataObjectType, (UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);

    if (mParamDumpHex &&
        (PciDoeHeader->DataObjectType != PCI_DOE_DATA_OBJECT_TYPE_SPDM) &&
        (PciDoeHeader->DataObjectType != PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM)) {
      printf ("  PCI_DOE Message:\n");
      DumpHex (Buffer, BufferSize);
    }
  } else {    
    printf ("\n");
  }
}
