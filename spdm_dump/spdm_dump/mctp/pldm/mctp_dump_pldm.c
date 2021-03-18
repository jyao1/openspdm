/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

void
dump_pldm_control_get_tid (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pldm_message_header_t  *pldm_message_header;
  boolean              is_req;
  uintn                header_size;

  pldm_message_header = buffer;
  is_req = ((pldm_message_header->instance_id & 0x80) != 0);
  printf ("GetTID_%s ", is_req ? "req" : "rsp");

  header_size = sizeof(pldm_message_header_t);
  if (!is_req) {
    header_size += sizeof(pldm_message_response_header_t);
  }

  if (is_req) {
    // request
    if (!m_param_quite_mode) {
      printf ("() ");
    }
  } else {
    // response
    if (buffer_size < header_size + 1) {
      printf ("\n");
      return ;
    }

    if (!m_param_quite_mode) {
      printf ("(tid=0x%02x) ", *((uint8 *)buffer + header_size));
    }
  }

  printf ("\n");
}

dispatch_table_entry_t m_pldm_control_dispatch[] = {
  {PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID,           "SetTID",          NULL },
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID,           "GetTID",          dump_pldm_control_get_tid},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION,  "GetPLDMVersion",  NULL},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES,    "GetPLDMTypes",    NULL},
  {PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS, "GetPLDMCommands", NULL},
};

void
dump_pldm_control (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pldm_message_header_t  *pldm_message_header;

  printf ("ControlDiscovery ");

  pldm_message_header = buffer;

  dump_dispatch_message (m_pldm_control_dispatch, ARRAY_SIZE(m_pldm_control_dispatch), pldm_message_header->pldm_command_code, (uint8 *)buffer, buffer_size);
}

dispatch_table_entry_t m_pldm_dispatch[] = {
  {PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY,           "ControlDiscovery", dump_pldm_control},
  {MCTP_MESSAGE_TYPE_SMBIOS,                      "SMBIOS",           NULL},
  {MCTP_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL, "Platform",         NULL},
  {MCTP_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION,  "BIOS",             NULL},
  {MCTP_MESSAGE_TYPE_FRU_DATA,                    "FRU",              NULL},
  {MCTP_MESSAGE_TYPE_FIRMWARE_UPDATE,             "FirmwareUpdate",   NULL},
  {MCTP_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT,   "RedFish",          NULL},
  {MCTP_MESSAGE_TYPE_OEM,                         "OEM",              NULL},
};

void
dump_pldm_message (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pldm_message_header_t           *pldm_message_header;
  pldm_message_response_header_t  *pldm_response_header;
  boolean                       is_req;

  if (buffer_size < sizeof(pldm_message_header_t)) {
    printf ("\n");
    return ;
  }

  pldm_message_header = buffer;
  is_req = ((pldm_message_header->instance_id & 0x80) != 0);

  if (!is_req) {
    if (buffer_size < sizeof(pldm_message_header_t) + sizeof(pldm_message_response_header_t)) {
      printf ("\n");
      return ;
    }
  }

  if (is_req) {
    printf ("PLDM(0x%02x, 0x%02x, 0x%02x) ",
      pldm_message_header->instance_id,
      pldm_message_header->pldm_type,
      pldm_message_header->pldm_command_code
      );
  } else {
    pldm_response_header = (void *)(pldm_message_header + 1);
    printf ("PLDM(0x%02x, 0x%02x, 0x%02x, 0x%02x) ",
      pldm_message_header->instance_id,
      pldm_message_header->pldm_type,
      pldm_message_header->pldm_command_code,
      pldm_response_header->pldm_completion_code
      );
  }

  if (!m_param_quite_mode) {
    printf ("(ID=%x, D=%x, Rq=%x) ",
      pldm_message_header->instance_id & 0x1F,
      ((pldm_message_header->instance_id & 0x40) != 0) ? 1 : 0,
      ((pldm_message_header->instance_id & 0x80) != 0) ? 1 : 0
      );
  }

  dump_dispatch_message (m_pldm_dispatch, ARRAY_SIZE(m_pldm_dispatch), pldm_message_header->pldm_type & 0x3F, (uint8 *)buffer, buffer_size);
}
