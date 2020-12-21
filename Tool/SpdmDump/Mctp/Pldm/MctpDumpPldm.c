/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPldmControlGetTID (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PLDM_MESSAGE_HEADER  *PldmMessageHeader;
  BOOLEAN              IsReq;
  UINTN                HeaderSize;

  PldmMessageHeader = Buffer;
  IsReq = ((PldmMessageHeader->InstanceID & 0x80) != 0);
  printf ("GetTID_%s ", IsReq ? "req" : "rsp");

  HeaderSize = sizeof(PLDM_MESSAGE_HEADER);
  if (!IsReq) {
    HeaderSize += sizeof(PLDM_MESSAGE_RESPONSE_HEADER);
  }

  if (IsReq) {
    // Request
    if (!mParamQuiteMode) {
      printf ("() ");
    }
  } else {
    // Response
    if (BufferSize < HeaderSize + 1) {
      printf ("\n");
      return ;
    }

    if (!mParamQuiteMode) {
      printf ("(TID=0x%02x) ", *((UINT8 *)Buffer + HeaderSize));
    }
  }

  printf ("\n");
}

DISPATCH_TABLE_ENTRY mPldmControlDispatch[] = {
  {PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID,           "SetTID",          NULL },
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,           "GetTID",          DumpPldmControlGetTID},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION,  "GetPLDMVersion",  NULL},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES,    "GetPLDMTypes",    NULL},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS, "GetPLDMCommands", NULL},
};

VOID
DumpPldmControl (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PLDM_MESSAGE_HEADER  *PldmMessageHeader;

  printf ("ControlDiscovery ");

  PldmMessageHeader = Buffer;

  DumpDispatchMessage (mPldmControlDispatch, ARRAY_SIZE(mPldmControlDispatch), PldmMessageHeader->PldmCommandCode, (UINT8 *)Buffer, BufferSize);
}

DISPATCH_TABLE_ENTRY mPldmDispatch[] = {
  {PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,           "ControlDiscovery", DumpPldmControl},
  {MCTP_MESSAGE_TYPE_SMBIOS,                      "SMBIOS",           NULL},
  {MCTP_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL, "Platform",         NULL},
  {MCTP_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION,  "BIOS",             NULL},
  {MCTP_MESSAGE_TYPE_FRU_DATA,                    "FRU",              NULL},
  {MCTP_MESSAGE_TYPE_FIRMWARE_UPDATE,             "FirmwareUpdate",   NULL},
  {MCTP_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT,   "RedFish",          NULL},
  {MCTP_MESSAGE_TYPE_OEM,                         "OEM",              NULL},
};

VOID
DumpPldmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PLDM_MESSAGE_HEADER           *PldmMessageHeader;
  PLDM_MESSAGE_RESPONSE_HEADER  *PldmResponseHeader;
  BOOLEAN                       IsReq;

  if (BufferSize < sizeof(PLDM_MESSAGE_HEADER)) {
    printf ("\n");
    return ;
  }

  PldmMessageHeader = Buffer;
  IsReq = ((PldmMessageHeader->InstanceID & 0x80) != 0);

  if (!IsReq) {
    if (BufferSize < sizeof(PLDM_MESSAGE_HEADER) + sizeof(PLDM_MESSAGE_RESPONSE_HEADER)) {
      printf ("\n");
      return ;
    }
  }

  if (IsReq) {
    printf ("PLDM(0x%02x, 0x%02x, 0x%02x) ",
      PldmMessageHeader->InstanceID,
      PldmMessageHeader->PldmType,
      PldmMessageHeader->PldmCommandCode
      );
  } else {
    PldmResponseHeader = (VOID *)(PldmMessageHeader + 1);
    printf ("PLDM(0x%02x, 0x%02x, 0x%02x, 0x%02x) ",
      PldmMessageHeader->InstanceID,
      PldmMessageHeader->PldmType,
      PldmMessageHeader->PldmCommandCode,
      PldmResponseHeader->PldmCompletionCode
      );
  }

  if (!mParamQuiteMode) {
    printf ("(ID=%x, D=%x, Rq=%x) ",
      PldmMessageHeader->InstanceID & 0x1F,
      ((PldmMessageHeader->InstanceID & 0x40) != 0) ? 1 : 0,
      ((PldmMessageHeader->InstanceID & 0x80) != 0) ? 1 : 0
      );
  }

  DumpDispatchMessage (mPldmDispatch, ARRAY_SIZE(mPldmDispatch), PldmMessageHeader->PldmType & 0x3F, (UINT8 *)Buffer, BufferSize);
}
