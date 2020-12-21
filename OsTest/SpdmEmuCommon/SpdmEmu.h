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
#include <IndustryStandard/PciIdeKm.h>

#include "OsInclude.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "assert.h"
#include "time.h"
#include "SpdmEmuCommand.h"

extern UINT32  mUseTransportLayer;
extern UINT8   mUseVersion;
extern UINT32  mUseCapabilityFlags;
extern UINT32  mUseHashAlgo;
extern UINT32  mUseMeasurementHashAlgo;
extern UINT32  mUseAsymAlgo;
extern UINT16  mUseReqAsymAlgo;
extern UINT16  mUseDheAlgo;
extern UINT16  mUseAeadAlgo;
extern UINT16  mUseKeyScheduleAlgo;

#define TEST_PSK_DATA_STRING  "TestPskData"
#define TEST_PSK_HINT_STRING  "TestPskHint"

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

BOOLEAN
ReadResponderPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  );

BOOLEAN
ReadRequesterPrivateCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size
  );

BOOLEAN
ReadResponderPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadRequesterPublicCertificateChain (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadResponderRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
ReadRequesterRootPublicCertificate (
  OUT VOID    **Data,
  OUT UINTN   *Size,
  OUT VOID    **Hash,
  OUT UINTN   *HashSize
  );

BOOLEAN
TestSpdmAsymGetPrivateKeyFromPem (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *PemData,
  IN      UINTN        PemSize,
  IN      CONST CHAR8  *Password,
  OUT     VOID         **Context
  );

BOOLEAN
TestSpdmAsymSign (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

VOID
TestSpdmAsymFree (
  IN      UINT32       AsymAlgo,
  IN      VOID         *Context
  );

BOOLEAN
EFIAPI
SpdmRequesterDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

BOOLEAN
EFIAPI
SpdmResponderDataSignFunc (
  IN      UINT32       AsymAlgo,
  IN      CONST UINT8  *MessageHash,
  IN      UINTN        HashSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  );

BOOLEAN
EFIAPI
SpdmPskHandshakeSecretHkdfExpandFunc (
  IN      UINT32       HashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  );

BOOLEAN
EFIAPI
SpdmPskMasterSecretHkdfExpandFunc (
  IN      UINT32       HashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  );

void
ProcessArgs (
  char  *ProgramName,
  int   argc,
  char  *argv[ ]
  );

#endif
