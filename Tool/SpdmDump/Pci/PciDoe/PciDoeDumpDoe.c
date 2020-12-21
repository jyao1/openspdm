/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPciDoeDiscoveryMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_DOE_DISCOVERY_REQUEST           *DoeRequest;
  PCI_DOE_DISCOVERY_RESPONSE          *DoeResponse;
  STATIC BOOLEAN                      IsRequester = FALSE;

  IsRequester = (BOOLEAN)(!IsRequester);
  if (IsRequester) {
    if (BufferSize < sizeof(PCI_DOE_DISCOVERY_REQUEST)) {
      printf ("\n");
      return ;
    }
  } else {
    if (BufferSize < sizeof(PCI_DOE_DISCOVERY_RESPONSE)) {
      printf ("\n");
      return ;
    }
  }

  if (IsRequester) {
    printf ("REQ->RSP ");
  } else {
    printf ("RSP->REQ ");
  }

  printf ("DOE_DISCOVERY ");

  if (IsRequester) {
    DoeRequest = Buffer;
    printf ("(Index=%d) ", DoeRequest->Index);
  } else {
    DoeResponse = Buffer;
    printf ("(%d, %d, NextIndex=%d) ", DoeResponse->VendorId, DoeResponse->DataObjectType, DoeResponse->NextIndex);
  }
  
  printf ("\n");
}
