/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

PCAP_GLOBAL_HEADER  mPcapGlobalHeader;
FILE                *mPcapFile;
VOID                *mPcapPacketDataBuffer;

DISPATCH_TABLE_ENTRY mPcapDispatch[] = {
  {LINKTYPE_MCTP,    "MCTP",    DumpMctpPacket},
  {LINKTYPE_PCI_DOE, "PCI_DOE", DumpPciDoePacket},
};

CHAR8 *
DataLinkTypeToString (
  IN UINT32  DataLinkType
  )
{
  switch (DataLinkType) {
  case LINKTYPE_MCTP:
    return "MCTP";
  case LINKTYPE_PCI_DOE:
    return "PCI_DOE";
  default:
    return "<Unknown>";
  }
}

UINT32
GetMaxPacketLength (
  VOID
  )
{
  return mPcapGlobalHeader.SnapLen;
}

UINT32
GetDataLinkType (
  VOID
  )
{
  return mPcapGlobalHeader.Network;
}

VOID
DumpPcapGlobalHeader (
  IN PCAP_GLOBAL_HEADER  *PcapGlobalHeader
  )
{
  printf (
    "PcapFile: Magic - '%x', version%d.%d, DataLink - %d (%s), MaxPacketSize - %d\n",
    PcapGlobalHeader->MagicNumber,
    PcapGlobalHeader->VersionMajor,
    PcapGlobalHeader->VersionMinor,
    PcapGlobalHeader->Network,
    DataLinkTypeToString (PcapGlobalHeader->Network),
    PcapGlobalHeader->SnapLen
    );
}

BOOLEAN
OpenPcapPacketFile (
  IN CHAR8  *PcapFileName
  )
{

  if (PcapFileName == NULL) {
    return FALSE;
  }

  if ((mPcapFile = fopen (PcapFileName, "rb")) == NULL) {
    printf ("!!!Unable to open pcap file %s!!!\n", PcapFileName);
    return FALSE;
  }

  if (fread (&mPcapGlobalHeader, 1, sizeof(PCAP_GLOBAL_HEADER), mPcapFile) != sizeof(PCAP_GLOBAL_HEADER)) {
    printf ("!!!Unable to read the pcap global header!!!\n");
    return FALSE;
  }

  if ((mPcapGlobalHeader.MagicNumber != PCAP_GLOBAL_HEADER_MAGIC) &&
      (mPcapGlobalHeader.MagicNumber != PCAP_GLOBAL_HEADER_MAGIC_SWAPPED) &&
      (mPcapGlobalHeader.MagicNumber != PCAP_GLOBAL_HEADER_MAGIC_NANO) &&
      (mPcapGlobalHeader.MagicNumber != PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED) ) {
    printf ("!!!pcap file magic invalid '%x'!!!\n", mPcapGlobalHeader.MagicNumber);
    return FALSE;
  }
  
  DumpPcapGlobalHeader (&mPcapGlobalHeader);

  if (mPcapGlobalHeader.SnapLen == 0) {
    return FALSE;
  }

  mPcapPacketDataBuffer = (VOID *)malloc (mPcapGlobalHeader.SnapLen);
  if (mPcapPacketDataBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    return FALSE;
  }

  return TRUE;
}

VOID
ClosePcapPacketFile (
  VOID
  )
{
  if (mPcapFile != NULL) {
    fclose (mPcapFile);
    mPcapFile = NULL;
  }
  if (mPcapPacketDataBuffer != NULL) {
    free (mPcapPacketDataBuffer);
    mPcapPacketDataBuffer = NULL;
  }
}

VOID
DumpPcapPacketHeader (
  IN UINTN               Index,
  IN PCAP_PACKET_HEADER  *PcapPacketHeader
  )
{
  printf (
    "%d (%d) ",
    (UINT32)Index,
    PcapPacketHeader->TsSec
    );
}

VOID
DumpPcapPacket (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  DumpDispatchMessage (mPcapDispatch, ARRAY_SIZE(mPcapDispatch), mPcapGlobalHeader.Network, Buffer, BufferSize);
}

VOID
DumpPcap (
  VOID
  )
{
  PCAP_PACKET_HEADER  PcapPacketHeader;
  UINTN               Index;

  Index = 1;

  while (TRUE) {
    if (fread (&PcapPacketHeader, 1, sizeof(PCAP_PACKET_HEADER), mPcapFile) != sizeof(PCAP_PACKET_HEADER)) {
      return ;
    }
    DumpPcapPacketHeader (Index++, &PcapPacketHeader);
    if (PcapPacketHeader.InclLen == 0) {
      return ;
    }
    if (fread (mPcapPacketDataBuffer, 1, PcapPacketHeader.InclLen, mPcapFile) != PcapPacketHeader.InclLen) {
      return ;
    }
    DumpPcapPacket (mPcapPacketDataBuffer, PcapPacketHeader.InclLen);
  }
}

