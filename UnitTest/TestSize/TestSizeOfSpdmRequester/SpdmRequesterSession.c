/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequester.h"

RETURN_STATUS
DoSessionViaSpdm (
  IN VOID   *SpdmContext
  )
{
  RETURN_STATUS                    Status;
  UINT32                           SessionId;
  UINT8                            HeartbeatPeriod;
  UINT8                            MeasurementHash[MAX_HASH_SIZE];

  HeartbeatPeriod = 0;
  ZeroMem(MeasurementHash, sizeof(MeasurementHash));
  Status = SpdmStartSession (
             SpdmContext,
             FALSE, // KeyExchange
             SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
             0,
             &SessionId,
             &HeartbeatPeriod,
             MeasurementHash
             );
  if (RETURN_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "SpdmStartSession - %r\n", Status));
    return Status;
  }
  
  //
  // TBD - Set Key
  //

  Status = SpdmStopSession (SpdmContext, SessionId, 0);
  if (RETURN_ERROR(Status)) {
    DEBUG ((DEBUG_ERROR, "SpdmStopSession - %r\n", Status));
    return Status;
  }

  return Status;
}