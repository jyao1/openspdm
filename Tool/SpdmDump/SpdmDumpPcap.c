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
  IN UINTN   BufferSize,
  IN BOOLEAN Truncated
  )
{
  switch (mPcapGlobalHeader.Network) {
  case LINKTYPE_MCTP:
    DumpMctpPacket (Buffer, BufferSize, Truncated);
    return ;
  case LINKTYPE_PCI_DOE:
    DumpPciDoePacket (Buffer, BufferSize, Truncated);
    return ;
  default:
    return ;
  }
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
    if (fread (mPcapPacketDataBuffer, 1, PcapPacketHeader.InclLen, mPcapFile) != PcapPacketHeader.InclLen) {
      return ;
    }
    DumpPcapPacket (mPcapPacketDataBuffer, PcapPacketHeader.InclLen, PcapPacketHeader.InclLen != PcapPacketHeader.OrigLen);
  }
}
