/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

dispatch_table_entry_t m_mctp_dispatch[] = {
  {MCTP_MESSAGE_TYPE_MCTP_CONTROL,         "MctpControl",        NULL},
  {MCTP_MESSAGE_TYPE_PLDM,                 "PLDM",               dump_pldm_message},
  {MCTP_MESSAGE_TYPE_NCSI_CONTROL,         "NCSI",               NULL},
  {MCTP_MESSAGE_TYPE_ETHERNET,             "Ethernet",           NULL},
  {MCTP_MESSAGE_TYPE_NVME_MANAGEMENT,      "NVMe",               NULL},
  {MCTP_MESSAGE_TYPE_SPDM,                 "SPDM",               dump_spdm_message},
  {MCTP_MESSAGE_TYPE_SECURED_MCTP,         "SecuredSPDM",        dump_secured_spdm_message},
  {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI,   "VendorDefinedPci",   NULL},
  {MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA,  "VendorDefinedIana",  NULL},
};

void
dump_mctp_message (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  mctp_message_header_t  *mctp_message_header;
  uintn                header_size;

  header_size = sizeof(mctp_message_header_t);
  if (buffer_size < header_size) {
    printf ("\n");
    return ;
  }
  mctp_message_header = (mctp_message_header_t *)((uint8 *)buffer);

  printf ("MCTP(%d) ", mctp_message_header->message_type);

  if (m_param_dump_vendor_app ||
      (mctp_message_header->message_type == MCTP_MESSAGE_TYPE_SPDM) ||
      (mctp_message_header->message_type == MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
    dump_dispatch_message (m_mctp_dispatch, ARRAY_SIZE(m_mctp_dispatch), mctp_message_header->message_type, (uint8 *)buffer + header_size, buffer_size - header_size);

    if (m_param_dump_hex &&
        (mctp_message_header->message_type != MCTP_MESSAGE_TYPE_SPDM) &&
        (mctp_message_header->message_type != MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
      printf ("  MCTP message:\n");
      dump_hex (buffer, buffer_size);
    }
  } else {
    printf ("\n");
  }
}

void
dump_mctp_packet (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  uintn                header_size;

  header_size = sizeof(mctp_header_t);
  if (buffer_size < header_size) {
    return ;
  }

  dump_mctp_message ((uint8 *)buffer + header_size, buffer_size - header_size);
}