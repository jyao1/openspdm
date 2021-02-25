/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

extern VOID          *mSpdmContext;

/**
  This function sends GET_DIGEST, GET_CERTIFICATE, CHALLENGE
  to authenticate the device.

  This function is combination of SpdmGetDigest, SpdmGetCertificate, SpdmChallenge.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SlotMask                     The slots which deploy the CertificateChain.
  @param  TotalDigestBuffer            A pointer to a destination buffer to store the digest buffer.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  CertChainSize                On input, indicate the size in bytes of the destination buffer to store the digest buffer.
                                       On output, indicate the size in bytes of the certificate chain.
  @param  CertChain                    A pointer to a destination buffer to store the certificate chain.
  @param  MeasurementHashType          The type of the measurement hash.
  @param  MeasurementHash              A pointer to a destination buffer to store the measurement hash.

  @retval RETURN_SUCCESS               The authentication is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
SpdmAuthentication (
  IN     VOID                 *Context,
     OUT UINT8                *SlotMask,
     OUT VOID                 *TotalDigestBuffer,
  IN     UINT8                SlotNum,
  IN OUT UINTN                *CertChainSize,
     OUT VOID                 *CertChain,
  IN     UINT8                MeasurementHashType,
     OUT VOID                 *MeasurementHash
  )
{
  RETURN_STATUS         Status;

  if ((mExeConnection & EXE_CONNECTION_DIGEST) != 0) {
    Status = SpdmGetDigest (Context, SlotMask, TotalDigestBuffer);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }

  if ((mExeConnection & EXE_CONNECTION_CERT) != 0) {
    if (SlotNum != 0xFF) {
      Status = SpdmGetCertificate (Context, SlotNum, CertChainSize, CertChain);
      if (RETURN_ERROR(Status)) {
        return Status;
      }
    }
  }

  if ((mExeConnection & EXE_CONNECTION_CHAL) != 0) {
    Status = SpdmChallenge (Context, SlotNum, MeasurementHashType, MeasurementHash);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }
  return RETURN_SUCCESS;
}

/**
  This function executes SPDM authentication.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
DoAuthenticationViaSpdm (
  VOID
  )
{
  RETURN_STATUS         Status;
  VOID                  *SpdmContext;
  UINT8                 SlotMask;
  UINT8                 TotalDigestBuffer[MAX_HASH_SIZE * MAX_SPDM_SLOT_COUNT];
  UINT8                 MeasurementHash[MAX_HASH_SIZE];
  UINTN                 CertChainSize;
  UINT8                 CertChain[MAX_SPDM_CERT_CHAIN_SIZE];

  SpdmContext = mSpdmContext;

  ZeroMem (TotalDigestBuffer, sizeof(TotalDigestBuffer));
  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  ZeroMem (MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmAuthentication (
             SpdmContext,
             &SlotMask,
             &TotalDigestBuffer,
             mUseSlotId,
             &CertChainSize,
             CertChain,
             mUseMeasurementSummaryHashType,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}
