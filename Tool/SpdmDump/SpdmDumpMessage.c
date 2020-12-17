/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

typedef struct {
  UINT8 OpCode;
  CHAR8 *String;
} SPDM_OPCODE_STRING_ENTRY;

SPDM_OPCODE_STRING_ENTRY mSpdmOpcodeStringTable[] = {
  {SPDM_DIGESTS, "SPDM_DIGESTS"},
  {SPDM_CERTIFICATE, "SPDM_CERTIFICATE"},
  {SPDM_CHALLENGE_AUTH, "SPDM_CHALLENGE_AUTH"},
  {SPDM_VERSION, "SPDM_VERSION"},
  {SPDM_MEASUREMENTS, "SPDM_MEASUREMENTS"},
  {SPDM_CAPABILITIES, "SPDM_CAPABILITIES"},
  {SPDM_ALGORITHMS, "SPDM_ALGORITHMS"},
  {SPDM_VENDOR_DEFINED_RESPONSE, "SPDM_VENDOR_DEFINED_RESPONSE"},
  {SPDM_ERROR, "SPDM_ERROR"},
  {SPDM_KEY_EXCHANGE_RSP, "SPDM_KEY_EXCHANGE_RSP"},
  {SPDM_FINISH_RSP, "SPDM_FINISH_RSP"},
  {SPDM_PSK_EXCHANGE_RSP, "SPDM_PSK_EXCHANGE_RSP"},
  {SPDM_PSK_FINISH_RSP, "SPDM_PSK_FINISH_RSP"},
  {SPDM_HEARTBEAT_ACK, "SPDM_HEARTBEAT_ACK"},
  {SPDM_KEY_UPDATE_ACK, "SPDM_KEY_UPDATE_ACK"},
  {SPDM_ENCAPSULATED_REQUEST, "SPDM_ENCAPSULATED_REQUEST"},
  {SPDM_ENCAPSULATED_RESPONSE_ACK, "SPDM_ENCAPSULATED_RESPONSE_ACK"},
  {SPDM_END_SESSION_ACK, "SPDM_END_SESSION_ACK"},

  {SPDM_GET_DIGESTS, "SPDM_GET_DIGESTS"},
  {SPDM_GET_CERTIFICATE, "SPDM_GET_CERTIFICATE"},
  {SPDM_CHALLENGE, "SPDM_CHALLENGE"},
  {SPDM_GET_VERSION, "SPDM_GET_VERSION"},
  {SPDM_GET_MEASUREMENTS, "SPDM_GET_MEASUREMENTS"},
  {SPDM_GET_CAPABILITIES, "SPDM_GET_CAPABILITIES"},
  {SPDM_NEGOTIATE_ALGORITHMS, "SPDM_NEGOTIATE_ALGORITHMS"},
  {SPDM_VENDOR_DEFINED_REQUEST, "SPDM_VENDOR_DEFINED_REQUEST"},
  {SPDM_RESPOND_IF_READY, "SPDM_RESPOND_IF_READY"},
  {SPDM_KEY_EXCHANGE, "SPDM_KEY_EXCHANGE"},
  {SPDM_FINISH, "SPDM_FINISH"},
  {SPDM_PSK_EXCHANGE, "SPDM_PSK_EXCHANGE"},
  {SPDM_PSK_FINISH, "SPDM_PSK_FINISH"},
  {SPDM_HEARTBEAT, "SPDM_HEARTBEAT"},
  {SPDM_KEY_UPDATE, "SPDM_KEY_UPDATE"},
  {SPDM_GET_ENCAPSULATED_REQUEST, "SPDM_GET_ENCAPSULATED_REQUEST"},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE, "SPDM_DELIVER_ENCAPSULATED_RESPONSE"},
  {SPDM_END_SESSION, "SPDM_END_SESSION"},
};

CHAR8 *
SpdmOpCodeToString (
  IN UINT8  SpdmOpCode
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE(mSpdmOpcodeStringTable); Index++) {
    if (SpdmOpCode == mSpdmOpcodeStringTable[Index].OpCode) {
      return mSpdmOpcodeStringTable[Index].String;
    }
  }
  return "<Unknown>";
}

VOID
DumpSpdmPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize,
  IN BOOLEAN Truncated
  )
{
  SPDM_MESSAGE_HEADER  *SpdmHeader;
  if (BufferSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return ;
  }

  SpdmHeader = Buffer;

  printf ("SPDM(%x, 0x%02x) ", SpdmHeader->SPDMVersion, SpdmHeader->RequestResponseCode);

  if ((SpdmHeader->RequestResponseCode & 0x80) != 0) {
    printf ("REQ->RSP ");
  } else {
    printf ("RSP->REQ ");
  }

  printf ("%s ", SpdmOpCodeToString(SpdmHeader->RequestResponseCode));

  printf ("\n");
}

VOID
DumpSecuredSpdmPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize,
  IN BOOLEAN Truncated
  )
{
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *SecuredMessageHeader;
  if (BufferSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER)) {
    return ;
  }

  SecuredMessageHeader = Buffer;

  printf ("SecuredSPDM(0x%08x) ", SecuredMessageHeader->SessionId);
  // TBD
  printf ("\n");
}
