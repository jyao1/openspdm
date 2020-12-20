/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

DISPATCH_TABLE_ENTRY mMctpDispatch[] = {
  {MCTP_MESSAGE_TYPE_SPDM,         "SPDM",        DumpSpdmMessage},
  {MCTP_MESSAGE_TYPE_SECURED_MCTP, "SecuredSPDM", DumpSecuredSpdmMessage},
  {MCTP_MESSAGE_TYPE_PLDM,         "PLDM",        DumpPldmMessage},
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

  DumpDispatchMessage (mMctpDispatch, ARRAY_SIZE(mMctpDispatch), MctpMessageHeader->MessageType, (UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
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