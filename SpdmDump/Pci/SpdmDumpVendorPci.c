/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

DISPATCH_TABLE_ENTRY mSpdmPciProtocolDispatch[] = {
  {PCI_PROTOCAL_ID_IDE_KM,    "IDE_KM",    DumpPciIdeKmMessage},
};

#pragma pack(1)

typedef struct {
  UINT16               StandardID;
  UINT8                Len;
  UINT16               VendorID;
  UINT16               PayloadLength;
  PCI_PROTOCOL_HEADER  PciProtocol;
} SPDM_VENDOR_DEFINED_PCI_HEADER;

#pragma pack()

VOID
DumpSpdmVendorPci (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_VENDOR_DEFINED_PCI_HEADER  *VendorDefinedPciHeader;

  printf ("PCI ");

  if (BufferSize < sizeof(SPDM_VENDOR_DEFINED_PCI_HEADER)) {
    printf ("\n");
    return ;
  }
  VendorDefinedPciHeader = Buffer;

  if (!mParamQuiteMode) {
    printf ("(VendorID=0x%04x) ", VendorDefinedPciHeader->VendorID);
  }

  if (VendorDefinedPciHeader->Len != sizeof(VendorDefinedPciHeader->VendorID)) {
    printf ("\n");
    return ;
  }
  if (VendorDefinedPciHeader->VendorID != SPDM_VENDOR_ID_PCISIG) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(ProtID=0x%02x) ", VendorDefinedPciHeader->PciProtocol.ProtocolId);
  }

  if (VendorDefinedPciHeader->PayloadLength < sizeof(PCI_PROTOCOL_HEADER)) {
    printf ("\n");
    return ;
  }
  if (VendorDefinedPciHeader->PayloadLength > BufferSize - (OFFSET_OF(SPDM_VENDOR_DEFINED_PCI_HEADER, PciProtocol))) {
    printf ("\n");
    return ;
  }

  DumpDispatchMessage (
    mSpdmPciProtocolDispatch, ARRAY_SIZE(mSpdmPciProtocolDispatch),
    VendorDefinedPciHeader->PciProtocol.ProtocolId,
    (UINT8 *)Buffer + sizeof(SPDM_VENDOR_DEFINED_PCI_HEADER),
    VendorDefinedPciHeader->PayloadLength - sizeof(PCI_PROTOCOL_HEADER)
    );

  if (mParamDumpHex) {
    printf ("  PCI Vendor Message:\n");
    DumpHex (Buffer, BufferSize);
  }
}
