/** @file
  Definition for pcap link types extension for SPDM transport layer (MCTP/PCI_DOE)

  https://www.tcpdump.org/linktypes.html

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __LINK_TYPE_EX_H__
#define __LINK_TYPE_EX_H__

#pragma pack(1)

//
// 0 ~ 289 are defined by https://www.tcpdump.org/linktypes.html
//

#define LINKTYPE_MCTP      290  // 0x0122
#define LINKTYPE_PCI_DOE   291  // 0x0123

#pragma pack()

#endif
