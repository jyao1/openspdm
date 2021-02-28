/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmEmu.h"
#include <IndustryStandard/Pcap.h>
#include <IndustryStandard/LinkTypeEx.h>

#define PCAP_PACKET_MAX_SIZE  0x00010000

FILE   *mPcapFile;

BOOLEAN
OpenPcapPacketFile (
  IN CHAR8  *PcapFileName
  )
{
  PCAP_GLOBAL_HEADER  PcapGlobalHeader;

  if (PcapFileName == NULL) {
    return FALSE;
  }

  PcapGlobalHeader.MagicNumber  = PCAP_GLOBAL_HEADER_MAGIC;
  PcapGlobalHeader.VersionMajor = PCAP_GLOBAL_HEADER_VERSION_MAJOR;
  PcapGlobalHeader.VersionMinor = PCAP_GLOBAL_HEADER_VERSION_MINOR;
  PcapGlobalHeader.ThisZone = 0;
  PcapGlobalHeader.SigFigs = 0;
  PcapGlobalHeader.SnapLen = PCAP_PACKET_MAX_SIZE;
  if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
    PcapGlobalHeader.Network = LINKTYPE_MCTP;
  } else if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    PcapGlobalHeader.Network = LINKTYPE_PCI_DOE;
  } else {
    return FALSE;
  }

  if ((mPcapFile = fopen (PcapFileName, "wb")) == NULL) {
    printf ("!!!Unable to open pcap file %s!!!\n", PcapFileName);
    return FALSE;
  }

  if ((fwrite (&PcapGlobalHeader, 1, sizeof(PcapGlobalHeader), mPcapFile)) != sizeof(PcapGlobalHeader)) {
    printf ("!!!Write pcap file error!!!\n");
    ClosePcapPacketFile ();
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
AppendPcapPacketData (
  IN VOID    *Header, OPTIONAL
  IN UINTN   HeaderSize, OPTIONAL
  IN VOID    *Data,
  IN UINTN   Size
  )
{
  PCAP_PACKET_HEADER  PcapPacketHeader;
  UINTN               TotalSize;

  TotalSize = HeaderSize + Size;

  if (mPcapFile != NULL) {
    time_t rawtime;
    time (&rawtime);

    PcapPacketHeader.TsSec = (UINT32)rawtime;
    PcapPacketHeader.TsUsec = 0;

    PcapPacketHeader.InclLen = (UINT32)((TotalSize > PCAP_PACKET_MAX_SIZE) ? PCAP_PACKET_MAX_SIZE : TotalSize);
    PcapPacketHeader.OrigLen = (UINT32)TotalSize;

    if ((fwrite (&PcapPacketHeader, 1, sizeof(PcapPacketHeader), mPcapFile)) != sizeof(PcapPacketHeader)) {
      printf ("!!!Write pcap file error!!!\n");
      ClosePcapPacketFile ();
      return ;
    }

    if (TotalSize > PCAP_PACKET_MAX_SIZE) {
      TotalSize = PCAP_PACKET_MAX_SIZE;
    }

    if (HeaderSize != 0) {
      if ((fwrite (Header, 1, HeaderSize, mPcapFile)) != HeaderSize) {
        printf ("!!!Write pcap file error!!!\n");
        ClosePcapPacketFile ();
        return ;
      }
    }

    if ((fwrite (Data, 1, Size, mPcapFile)) != Size) {
      printf ("!!!Write pcap file error!!!\n");
      ClosePcapPacketFile ();
      return ;
    }
  }
}
