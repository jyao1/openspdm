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
// | Global header | Packet header | Packet data | Packet header | Packet data | Packet header | Packet data | ... |
// +---------------+---------------+-------------+---------------+-------------+---------------+-------------+-----+
//

typedef struct {
  uint32 magic_number;
  uint16 version_major;
  uint16 version_minor;
  int32  this_zone;
  uint32 sig_figs;
  uint32 snap_len;
  uint32 network; // data Link Type
} pcap_global_header_t;

#define PCAP_GLOBAL_HEADER_MAGIC          0xa1b2c3d4
#define PCAP_GLOBAL_HEADER_MAGIC_SWAPPED  0xd4c3b2a1

#define PCAP_GLOBAL_HEADER_MAGIC_NANO          0xa1b23c4d
#define PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED  0x4d3cb2a1

#define PCAP_GLOBAL_HEADER_VERSION_MAJOR  0x0002
#define PCAP_GLOBAL_HEADER_VERSION_MINOR  0x0004

typedef struct {
  uint32 ts_sec;
  // PCAP_GLOBAL_HEADER_MAGIC      : MicroSecond
  // PCAP_GLOBAL_HEADER_MAGIC_NANO : NanoSecond
  uint32 ts_usec;
  uint32 incl_len;
  uint32 orig_len;
} pcap_packet_header_t;

#pragma pack()

#endif
