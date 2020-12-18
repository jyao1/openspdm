/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

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
    return ;
  }
  MctpMessageHeader = (MCTP_MESSAGE_HEADER *)((UINT8 *)Buffer);

  printf ("MCTP(%d) ", MctpMessageHeader->MessageType);

  switch (MctpMessageHeader->MessageType) {
  case MCTP_MESSAGE_TYPE_SPDM:
    DumpSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
    break;
  case MCTP_MESSAGE_TYPE_SECURED_MCTP:
    DumpSecuredSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
    break;
  case MCTP_MESSAGE_TYPE_PLDM:
    // TBD
  default:
    printf ("\n");
    break;
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