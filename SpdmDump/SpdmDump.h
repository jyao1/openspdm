/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_DUMP_H__
#define __SPDM_DUMP_H__

#include <Base.h>
#include <IndustryStandard/Spdm.h>
#include <IndustryStandard/SpdmSecuredMessage.h>
#include <IndustryStandard/MctpBinding.h>
#include <IndustryStandard/Pldm.h>
#include <IndustryStandard/PciDoeBinding.h>
#include <IndustryStandard/PciIdeKm.h>
#include <IndustryStandard/Pcap.h>
#include <IndustryStandard/LinkTypeEx.h>

#include <Library/SpdmCommonLib.h>
#include <Library/SpdmTransportMctpLib.h>
#include <Library/SpdmTransportPciDoeLib.h>

#include "OsInclude.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef
VOID
(*DUMP_MESSAGE) (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

typedef struct {
  UINT32        Id;
  CHAR8         *Name;
  DUMP_MESSAGE  DumpFunc;
} DISPATCH_TABLE_ENTRY;

DISPATCH_TABLE_ENTRY *
GetDispatchEntryById (
  IN DISPATCH_TABLE_ENTRY  *DispatchTable,
  IN UINTN                 DispatchTableCount,
  IN UINT32                Id
  );

VOID
DumpDispatchMessage (
  IN DISPATCH_TABLE_ENTRY  *DispatchTable,
  IN UINTN                 DispatchTableCount,
  IN UINT32                Id,
  IN VOID                  *Buffer,
  IN UINTN                 BufferSize
  );

typedef struct {
  UINT32  Value;
  CHAR8   *Name;
} VALUE_STRING_ENTRY;

VOID
DumpEntryFlagsAll (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Flags
  );

VOID
DumpEntryFlags (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Flags
  );

VOID
DumpEntryValue (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Value
  );

BOOLEAN
InitSpdmDump (
  VOID
  );

VOID
DeinitSpdmDump (
  VOID
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
DumpPcap (
  VOID
  );

UINT32
GetDataLinkType (
  VOID
  );

UINT32
GetMaxPacketLength (
  VOID
  );

VOID
DumpHexStr (
  IN UINT8  *Data,
  IN UINTN  Size
  );

VOID
DumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  );

VOID
DumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  );

VOID
DumpMctpPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpPciDoePacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpMctpMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpSecuredSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpSpdmOpaqueData (
  IN UINT8    *OpaqueData,
  IN UINT16   OpaqueLength
  );

VOID
DumpPldmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpPciDoeDiscoveryMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpSpdmVendorPci (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

VOID
DumpPciIdeKmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

RETURN_STATUS
SpdmDumpSessionDataProvision (
  IN VOID                         *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      NeedMutAuth,
  IN BOOLEAN                      IsRequester
  );

RETURN_STATUS
SpdmDumpSessionDataCheck (
  IN VOID                         *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  );

BOOLEAN
HexStringToBuffer (
  IN  CHAR8   *HexString,
  OUT VOID    **Buffer,
  OUT UINTN   *BufferSize
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
OpenOutputFile (
  IN CHAR8   *FileName
  );

extern BOOLEAN  mParamQuiteMode;
extern BOOLEAN  mParamAllMode;
extern BOOLEAN  mParamDumpVendorApp;
extern BOOLEAN  mParamDumpHex;
extern CHAR8    *mParamOutRspCertChainFileName;
extern CHAR8    *mParamOutReqCertChainFileName;

extern VOID    *mRequesterCertChainBuffer;
extern UINTN   mRequesterCertChainBufferSize;
extern VOID    *mResponderCertChainBuffer;
extern UINTN   mResponderCertChainBufferSize;
extern VOID    *mDheSecretBuffer;
extern UINTN   mDheSecretBufferSize;
extern VOID    *mPskBuffer;
extern UINTN   mPskBufferSize;

#endif