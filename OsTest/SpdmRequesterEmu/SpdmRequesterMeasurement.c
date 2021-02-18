/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterEmu.h"

extern VOID          *mSpdmContext;

/**
  This function executes SPDM measurement and extend to TPM.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveGetMeasurement (
  IN VOID          *SpdmContext,
  IN UINT32        *SessionId
  )
{
  RETURN_STATUS                             Status;
  UINT8                                     NumberOfBlocks;
  UINT8                                     NumberOfBlock;
  UINT32                                    MeasurementRecordLength;
  UINT8                                     MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  UINT8                                     Index;
  UINT8                                     RequestAttribute;

  if (mUseMeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
    //
    // Request all at one time.
    //
    RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    MeasurementRecordLength = sizeof(MeasurementRecord);
    Status = SpdmGetMeasurement (
               SpdmContext,
               SessionId,
               RequestAttribute,
               SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,
               mUseSlotId & 0xF,
               &NumberOfBlock,
               &MeasurementRecordLength,
               MeasurementRecord
               );
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else {
    RequestAttribute = 0;
    //
    // 1. Query the total number of measurements available.
    //
    Status = SpdmGetMeasurement (
              SpdmContext,
              SessionId,
              RequestAttribute,
              SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
              mUseSlotId & 0xF,
              &NumberOfBlocks,
              NULL,
              NULL
              );
    if (RETURN_ERROR(Status)) {
      return Status;
    }
    DEBUG((DEBUG_INFO, "NumberOfBlocks - 0x%x\n", NumberOfBlocks));
    for (Index = 1; Index <= NumberOfBlocks; Index++) {
      DEBUG((DEBUG_INFO, "Index - 0x%x\n", Index));
      //
      // 2. query measurement one by one
      // get signature in last message only.
      //
      if (Index == NumberOfBlocks) {
        RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
      }
      MeasurementRecordLength = sizeof(MeasurementRecord);
      Status = SpdmGetMeasurement (
                SpdmContext,
                SessionId,
                RequestAttribute,
                Index,
                mUseSlotId & 0xF,
                &NumberOfBlock,
                &MeasurementRecordLength,
                MeasurementRecord
                );
      if (RETURN_ERROR(Status)) {
        return Status;
      }
    }
  }

  return RETURN_SUCCESS;
}

/**
  This function executes SPDM measurement and extend to TPM.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
DoMeasurementViaSpdm (
  IN UINT32        *SessionId
  )
{
  RETURN_STATUS         Status;
  VOID                  *SpdmContext;

  SpdmContext = mSpdmContext;
  
  Status = SpdmSendReceiveGetMeasurement (SpdmContext, SessionId);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}
