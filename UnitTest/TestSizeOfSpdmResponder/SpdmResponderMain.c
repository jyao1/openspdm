/** @file
  TPA Core

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponder.h"

VOID
SpdmDispatch (
  VOID
  )
{
  VOID           *SpdmContext;
  RETURN_STATUS  Status;

  SpdmContext = SpdmServerInit ();
  if (SpdmContext == NULL) {
    return ;
  }

  while (TRUE) {
    Status = SpdmResponderDispatchMessage (SpdmContext);
    if (Status != RETURN_UNSUPPORTED) {
      continue;
    }
  }
  return ;
}

/**
  Main entry point to DXE Core.

  @param  HobStart               Pointer to the beginning of the HOB List from PEI.

  @return This function should never return.

**/
VOID
EFIAPI
ModuleEntryPoint (
  VOID
  )
{
  SpdmDispatch ();

  return ;
}