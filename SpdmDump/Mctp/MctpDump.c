/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

DISPATCH_TABLE_ENTRY mMctpDispatch[] = {
  {MCTP_MESSAGE_TYPE_MCTP_CONTROL,         "MctpControl",        NULL},
  {MCTP_MESSAGE_TYPE_PLDM,                 "PLDM",               DumpPldmMessage},
  {MCTP_MESSAGE_TYPE_NCSI_CONTROL,         "NCSI",               NULL},
  {MCTP_MESSAGE_TYPE_ETHERNET,             "Ethernet",           NULL},
  {MCTP_MESSAGE_TYPE_NVME_MANAGEMENT,      "NVMe",               NULL},
  {MCTP_MESSAGE_TYPE_SPDM,                 "SPDM",               DumpSpdmMessage},
  {MCTP_MESSAGE_TYPE_SECURED_MCTP,         "SecuredSPDM",        DumpSecuredSpdmMessage},
  {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI,   "VendorDefinedPci",   NULL},
  {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA,  "VendorDefinedIana",  NULL},
};

VOID
DumpMctpMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  MCTP_MESSAGE_HEADER  *MctpMessageHeader;
  UINTN                HeaderSize;

  HeaderSize = sizeof(MCTP_MESSAGE_HEADER);
  if (BufferSize < HeaderSize) {
    printf ("\n");
    return ;
  }
  MctpMessageHeader = (MCTP_MESSAGE_HEADER *)((UINT8 *)Buffer);

  printf ("MCTP(%d) ", MctpMessageHeader->MessageType);

  if (mParamDumpVendorApp ||
      (MctpMessageHeader->MessageType == MCTP_MESSAGE_TYPE_SPDM) ||
      (MctpMessageHeader->MessageType == MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
    DumpDispatchMessage (mMctpDispatch, ARRAY_SIZE(mMctpDispatch), MctpMessageHeader->MessageType, (UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);

    if (mParamDumpHex &&
        (MctpMessageHeader->MessageType != MCTP_MESSAGE_TYPE_SPDM) &&
        (MctpMessageHeader->MessageType != MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
      printf ("  MCTP Message:\n");
      DumpHex (Buffer, BufferSize);
    }
  } else {
    printf ("\n");
  }
}

VOID
DumpMctpPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                HeaderSize;

  HeaderSize = sizeof(MCTP_HEADER);
  if (BufferSize < HeaderSize) {
    return ;
  }

  DumpMctpMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
}