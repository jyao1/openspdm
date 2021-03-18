/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

void
dump_pci_doe_discovery_message (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  pci_doe_discovery_request_t           *doe_request;
  pci_doe_discovery_response_t          *doe_response;
  static boolean                      is_requester = FALSE;

  is_requester = (boolean)(!is_requester);
  if (is_requester) {
    if (buffer_size < sizeof(pci_doe_discovery_request_t)) {
      printf ("\n");
      return ;
    }
  } else {
    if (buffer_size < sizeof(pci_doe_discovery_response_t)) {
      printf ("\n");
      return ;
    }
  }

  if (is_requester) {
    printf ("REQ->RSP ");
  } else {
    printf ("RSP->REQ ");
  }

  printf ("DOE_DISCOVERY ");

  if (is_requester) {
    doe_request = buffer;
    printf ("(index=%d) ", doe_request->index);
  } else {
    doe_response = buffer;
    printf ("(%d, %d, next_index=%d) ", doe_response->vendor_id, doe_response->data_object_type, doe_response->next_index);
  }
  
  printf ("\n");
}
