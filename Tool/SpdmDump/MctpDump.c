/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpMctpPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize,
  IN BOOLEAN Truncated
  )
{
  MCTP_MESSAGE_HEADER  *MctpMessageHeader;
  UINTN                HeaderSize;

  HeaderSize = sizeof(MCTP_HEADER) + sizeof(MCTP_MESSAGE_HEADER);
  if (BufferSize < HeaderSize) {
    return ;
  }
  MctpMessageHeader = (MCTP_MESSAGE_HEADER *)((UINT8 *)Buffer + sizeof(MCTP_HEADER));

  printf ("MCTP(%d) ", MctpMessageHeader->MessageType);

  switch (MctpMessageHeader->MessageType) {
  case MCTP_MESSAGE_TYPE_SPDM:
    DumpSpdmPacket ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize, Truncated);
    break;
  case MCTP_MESSAGE_TYPE_SECURED_MCTP:
    DumpSecuredSpdmPacket ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize, Truncated);
    break;
  case MCTP_MESSAGE_TYPE_PLDM:
    // TBD
  default:
    printf ("\n");
    break;
  }

}