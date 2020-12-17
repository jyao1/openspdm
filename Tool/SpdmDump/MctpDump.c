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
  MCTP_MESSAGE_HEADER  *MctpHeader;
  if (BufferSize < sizeof(MCTP_MESSAGE_HEADER)) {
    return ;
  }
  MctpHeader = Buffer;

  printf ("MCTP(%d) ", MctpHeader->MessageType);

  switch (MctpHeader->MessageType) {
  case MCTP_MESSAGE_TYPE_SPDM:
    DumpSpdmPacket ((UINT8 *)Buffer + sizeof(MCTP_MESSAGE_HEADER), BufferSize - sizeof(MCTP_MESSAGE_HEADER), Truncated);
    break;
  case MCTP_MESSAGE_TYPE_SECURED_MCTP:
    DumpSecuredSpdmPacket ((UINT8 *)Buffer + sizeof(MCTP_MESSAGE_HEADER), BufferSize - sizeof(MCTP_MESSAGE_HEADER), Truncated);
    break;
  case MCTP_MESSAGE_TYPE_PLDM:
    // TBD
    break;
  default:
    break;
  }

}