/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

dispatch_table_entry_t m_pci_doe_dispatch[] = {
  {PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, "DoeDiscovery",  dump_pci_doe_discovery_message},
  {PCI_DOE_DATA_OBJECT_TYPE_SPDM,          "SPDM",          dump_spdm_message},
  {PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM,  "SecuredSPDM",   dump_secured_spdm_message},
};

void
dump_pci_doe_packet (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pci_doe_data_object_header_t  *pci_doe_header;
  uintn                       header_size;

  header_size = sizeof(pci_doe_data_object_header_t);
  if (buffer_size < header_size) {
    printf ("\n");
    return ;
  }
  pci_doe_header = buffer;

  printf ("PCI_DOE(%d, %d) ", pci_doe_header->vendor_id, pci_doe_header->data_object_type);

  if (pci_doe_header->vendor_id != PCI_DOE_VENDOR_ID_PCISIG) {
    printf ("\n");
    return ;
  }
  
  if (m_param_dump_vendor_app ||
      (pci_doe_header->data_object_type == PCI_DOE_DATA_OBJECT_TYPE_SPDM) ||
      (pci_doe_header->data_object_type == PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM)) {
    dump_dispatch_message (m_pci_doe_dispatch, ARRAY_SIZE(m_pci_doe_dispatch), pci_doe_header->data_object_type, (uint8 *)buffer + header_size, buffer_size - header_size);

    if (m_param_dump_hex &&
        (pci_doe_header->data_object_type != PCI_DOE_DATA_OBJECT_TYPE_SPDM) &&
        (pci_doe_header->data_object_type != PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM)) {
      printf ("  PCI_DOE message:\n");
      dump_hex (buffer, buffer_size);
    }
  } else {    
    printf ("\n");
  }
}
