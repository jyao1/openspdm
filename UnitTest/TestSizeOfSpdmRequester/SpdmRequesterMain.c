/** @file
  TPA Core

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequester.h"

VOID
SpdmDispatch (
  VOID
  )
{
  VOID           *SpdmContext;
  RETURN_STATUS  Status;

  SpdmContext = SpdmClientInit ();
  if (SpdmContext == NULL) {
    return ;
  }

  Status = DoAuthenticationViaSpdm (SpdmContext);
  if (RETURN_ERROR (Status)) {
    return ;
  }

  Status = DoSessionViaSpdm (SpdmContext);
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