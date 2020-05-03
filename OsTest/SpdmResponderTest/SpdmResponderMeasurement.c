/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderTest.h"

#define SHA256_HASH_SIZE  32

#define BLOCK_NUMBER   4

BOOLEAN
EFIAPI
Sha256HashAll (
  IN VOID  *Data,
  IN UINTN DataSize,
  OUT VOID *Hash
  );

typedef struct {
  SPDM_MEASUREMENT_BLOCK_COMMON_HEADER  MeasurementBlockCommonHeader;
  SPDM_MEASUREMENT_BLOCK_DMTF_HEADER    MeasurementBlockDmtfHeader;
  UINT8                                 HashValue[SHA256_HASH_SIZE];
} MY_SPDM_MEASUREMENT_BLOCK;

BOOLEAN
RegisterMeasurement (
  OUT VOID                            **DeviceMeasurement,
  OUT UINTN                           *DeviceMeasurementSize,
  OUT UINT8                           *DeviceMeasurementCount
  )
{
  MY_SPDM_MEASUREMENT_BLOCK    *MeasurementBlock;
  UINT16                       HashSize;
  UINT8                        Index;

  *DeviceMeasurementCount = BLOCK_NUMBER;
  *DeviceMeasurementSize = BLOCK_NUMBER * sizeof(MY_SPDM_MEASUREMENT_BLOCK);
  *DeviceMeasurement = malloc (BLOCK_NUMBER * sizeof(MY_SPDM_MEASUREMENT_BLOCK));
  if (*DeviceMeasurement == NULL) {
    return FALSE;
  }

  MeasurementBlock = *DeviceMeasurement;
  HashSize = SHA256_HASH_SIZE;

  for (Index = 0; Index < BLOCK_NUMBER; Index++) {
    MeasurementBlock[Index].MeasurementBlockCommonHeader.Index = Index + 1;
    MeasurementBlock[Index].MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    MeasurementBlock[Index].MeasurementBlockCommonHeader.MeasurementSize = (UINT16)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + HashSize);
    switch (Index) {
    case 0:
      MeasurementBlock[Index].MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM;
      break;
    case 1:
      MeasurementBlock[Index].MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE;
      break;
    case 2:
      MeasurementBlock[Index].MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HARDWARE_CONFIGURATION;
      break;
    case 3:
      MeasurementBlock[Index].MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_FIRMWARE_CONFIGURATION;
      break;
    default:
      ASSERT(FALSE);
      break;
    }
    MeasurementBlock[Index].MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize = HashSize;
    SetMem (
      MeasurementBlock[Index].HashValue,
      HashSize,
      (UINT8)(Index + 1)
      );
  }

  return TRUE;
}