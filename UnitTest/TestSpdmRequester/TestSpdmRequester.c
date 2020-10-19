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
int SpdmRequesterNegotiateAlgorithmTestMain (void);
int SpdmRequesterGetDigestTestMain (void);
int SpdmRequesterGetCertificateTestMain (void);
int SpdmRequesterChallengeTestMain (void);
int SpdmRequesterGetMeasurementTestMain (void);

int main(void) {
  SpdmRequesterGetVersionTestMain();

  SpdmRequesterGetCapabilityTestMain();

  SpdmRequesterNegotiateAlgorithmTestMain();

  SpdmRequesterGetDigestTestMain();

  SpdmRequesterGetCertificateTestMain();

  SpdmRequesterChallengeTestMain();

  SpdmRequesterGetMeasurementTestMain();
  return 0;
}
