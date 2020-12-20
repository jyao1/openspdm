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
#include <IndustryStandard/PciDoeBinding.h>
#include <IndustryStandard/Pcap.h>
#include <IndustryStandard/LinkTypeEx.h>

#include <Library/SpdmSecuredMessageLib.h>
#include <SpdmCommonLibInternal.h>

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
DumpPciIdeKmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  );

RETURN_STATUS
SpdmCalculateSessionHandshakeKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN UINT32                       SessionId,
  IN BOOLEAN                      IsRequester
  );

RETURN_STATUS
SpdmCalculateSessionDataKey (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
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

extern BOOLEAN  mParamQuiteMode;
extern BOOLEAN  mParamAllMode;
extern BOOLEAN  mParamDumpAsn1;
extern BOOLEAN  mParamDumpVendorApp;
extern BOOLEAN  mParamDumpHex;

extern VOID    *mRequesterCertChainBuffer;
extern UINTN   mRequesterCertChainBufferSize;
extern VOID    *mResponderCertChainBuffer;
extern UINTN   mResponderCertChainBufferSize;
extern VOID    *mDheSecretBuffer;
extern UINTN   mDheSecretBufferSize;
extern VOID    *mPskBuffer;
extern UINTN   mPskBufferSize;

#endif