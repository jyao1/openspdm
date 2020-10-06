/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequester.h"

/**
  This function executes SPDM authentication.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
DoAuthenticationViaSpdm (
  IN VOID   *SpdmContext
  )
{
  RETURN_STATUS         Status;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
  UINT8                 MeasurementHash[MAX_HASH_SIZE];
  UINTN                 CertChainSize;
  UINT8                 CertChain[MAX_SPDM_CERT_CHAIN_SIZE];

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmAuthentication (
             SpdmContext,
             &SlotMask,
             &TotalDigestBuffer,
             0,
             &CertChainSize,
             CertChain,
             SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}
