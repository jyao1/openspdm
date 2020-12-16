/** @file
  Definition for pcap file format and link type

  https://www.tcpdump.org/manpages/pcap-savefile.5.txt

  https://wiki.wireshark.org/Development/LibpcapFileFormat

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PCAP_H__
#define __PCAP_H__

#pragma pack(1)

//
// PCAP file format:
// +---------------+---------------+-------------+---------------+-------------+---------------+-------------+-----+
// | Global Header | Packet Header | Packet Data | Packet Header | Packet Data | Packet Header | Packet Data | ... |
// +---------------+---------------+-------------+---------------+-------------+---------------+-------------+-----+
//

typedef struct {
  UINT32 MagicNumber;
  UINT16 VersionMajor;
  UINT16 VersionMinor;
  INT32  ThisZone;
  UINT32 SigFigs;
  UINT32 SnapLen;
  UINT32 Network; // Data Link Type
} PCAP_GLOBAL_HEADER;

#define PCAP_GLOBAL_HEADER_MAGIC          0xa1b2c3d4
#define PCAP_GLOBAL_HEADER_MAGIC_SWAPPED  0xd4c3b2a1

#define PCAP_GLOBAL_HEADER_MAGIC_NANO          0xa1b23c4d
#define PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED  0x4d3cb2a1

#define PCAP_GLOBAL_HEADER_VERSION_MAJOR  0x0002
#define PCAP_GLOBAL_HEADER_VERSION_MINOR  0x0004

typedef struct {
  UINT32 TsSec;
  // PCAP_GLOBAL_HEADER_MAGIC      : MicroSecond
  // PCAP_GLOBAL_HEADER_MAGIC_NANO : NanoSecond
  UINT32 TsUsec;
  UINT32 InclLen;
  UINT32 OrigLen;
} PCAP_PACKET_HEADER;

#pragma pack()

#endif
