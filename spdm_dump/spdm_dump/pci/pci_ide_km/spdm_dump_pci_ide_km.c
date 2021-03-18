/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

void
dump_pci_ide_km_query (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pci_ide_km_query_t  *query;

  printf ("QUERY ");

  if (buffer_size < sizeof(pci_ide_km_query_t)) {
    printf ("\n");
    return ;
  }

  query = buffer;

  if (!m_param_quite_mode) {
    printf ("(port=0x%02x) ", query->port_index);
  }

  printf ("\n");
}

void
dump_pci_ide_km_query_resp (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pci_ide_km_query_resp_t  *query_resp;

  printf ("QUERY_RESP ");

  if (buffer_size < sizeof(pci_ide_km_query_resp_t)) {
    printf ("\n");
    return ;
  }

  query_resp = buffer;

  if (!m_param_quite_mode) {
    printf ("(port=0x%02x, S%02xB%02xDF%02x, MaxPort=0x%02x) ",
      query_resp->port_index,
      query_resp->segment,
      query_resp->bus_num,
      query_resp->dev_func_num,
      query_resp->max_port_index
      );
  }

  printf ("\n");
}

void
dump_pci_ide_km_key_program (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  printf ("KEY_PROG ");
  printf ("\n");
}

void
dump_pci_ide_km_key_program_ack (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  printf ("KP_ACK ");
  printf ("\n");
}

void
dump_pci_ide_km_key_set_go (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  printf ("K_SET_GO ");
  printf ("\n");
}

void
dump_pci_ide_km_key_set_stop (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  printf ("K_SET_STOP ");
  printf ("\n");
}

void
dump_pci_ide_km_key_set_gostop_ack (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  printf ("K_SET_GOSTOP_ACK ");
  printf ("\n");
}

dispatch_table_entry_t m_pci_ide_km_dispatch[] = {
  {PCI_IDE_KM_OBJECT_ID_QUERY,             "QUERY",             dump_pci_ide_km_query},
  {PCI_IDE_KM_OBJECT_ID_QUERY_RESP,        "QUERY_RESP",        dump_pci_ide_km_query_resp},
  {PCI_IDE_KM_OBJECT_ID_KEY_PROG,          "KEY_PROG",          dump_pci_ide_km_key_program},
  {PCI_IDE_KM_OBJECT_ID_KP_ACK,            "KP_ACK",            dump_pci_ide_km_key_program_ack},
  {PCI_IDE_KM_OBJECT_ID_K_SET_GO,          "K_SET_GO",          dump_pci_ide_km_key_set_go},
  {PCI_IDE_KM_OBJECT_ID_K_SET_STOP,        "K_SET_STOP",        dump_pci_ide_km_key_set_stop},
  {PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK,  "K_SET_GOSTOP_ACK",  dump_pci_ide_km_key_set_gostop_ack},
};

void
dump_pci_ide_km_message (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pci_ide_km_header_t  *pci_ide_km_header;

  if (buffer_size < sizeof(pci_ide_km_header_t)) {
    printf ("\n");
    return ;
  }
  pci_ide_km_header = buffer;

  printf ("IDE_KM(0x%02x) ", pci_ide_km_header->object_id);

  dump_dispatch_message (m_pci_ide_km_dispatch, ARRAY_SIZE(m_pci_ide_km_dispatch), pci_ide_km_header->object_id, (uint8 *)buffer, buffer_size);
}
