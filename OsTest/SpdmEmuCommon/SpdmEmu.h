/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_H__
#define __SPDM_TEST_H__

#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmCommonLib.h>
#include <IndustryStandard/MctpBinding.h>
#include <IndustryStandard/Pldm.h>
#include <IndustryStandard/PciDoeBinding.h>
#include <IndustryStandard/PciIdeKm.h>
#include <SpdmDeviceSecretLibInternal.h>

#include "OsInclude.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "assert.h"
#include "time.h"
#include "SpdmEmuCommand.h"

extern UINT32  mUseTransportLayer;
extern UINT8   mUseVersion;
extern UINT8   mUseSecuredMessageVersion;
extern UINT32  mUseRequesterCapabilityFlags;
extern UINT32  mUseResonderCapabilityFlags;
extern UINT32  mUseCapabilityFlags;

extern UINT8   mUseMutAuth;
extern UINT8   mUseMeasurementSummaryHashType;
extern UINT8   mUseMeasurementOperation;
extern UINT8   mUseSlotId;
extern UINT8   mUseSlotCount;

extern UINT32  mUseHashAlgo;
extern UINT32  mUseMeasurementHashAlgo;
extern UINT32  mUseAsymAlgo;
extern UINT16  mUseReqAsymAlgo;

extern UINT8   mSupportMeasurementSpec;
extern UINT32  mSupportMeasurementHashAlgo;
extern UINT32  mSupportHashAlgo;
extern UINT32  mSupportAsymAlgo;
extern UINT16  mSupportReqAsymAlgo;
extern UINT16  mSupportDheAlgo;
extern UINT16  mSupportAeadAlgo;
extern UINT16  mSupportKeyScheduleAlgo;

VOID
DumpHexStr (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

VOID
DumpHex (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

BOOLEAN
SendPlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend
  );

BOOLEAN
ReceivePlatformData (
  IN  SOCKET           Socket,
  OUT UINT32           *Command,
  OUT UINT8            *ReceiveBuffer,
  IN OUT UINTN         *BytesToReceive
  );

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  );

BOOLEAN
WriteOutputFile (
  IN CHAR8   *FileName,
  IN VOID    *FileData,
  IN UINTN   FileSize
  );

BOOLEAN
OpenPcapPacketFile (
  IN CHAR8  *PcapFileName
  );

VOID
ClosePcapPacketFile (
  VOID
  );

VOID
AppendPcapPacketData (
  IN VOID    *Header, OPTIONAL
  IN UINTN   HeaderSize, OPTIONAL
  IN VOID    *Data,
  IN UINTN   Size
  );

void
ProcessArgs (
  char  *ProgramName,
  int   argc,
  char  *argv[ ]
  );

#endif
