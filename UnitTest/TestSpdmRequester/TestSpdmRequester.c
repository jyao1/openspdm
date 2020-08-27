/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

int SpdmRequesterGetVersionTestMain (void);
int SpdmRequesterGetCapabilityTestMain (void);


int main(void) {
  SpdmRequesterGetVersionTestMain();

  SpdmRequesterGetCapabilityTestMain();

  return 0;
}
