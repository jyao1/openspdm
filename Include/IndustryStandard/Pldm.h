/** @file
  Definitions of DSP0240 Platform Level Data Model (PLDM) Base Specification
  version 1.0.0 in Distributed Management Task Force (DMTF).

  Definitions of DSP0245 Platform Level Data Model (PLDM) IDs and Codes Specification
  version 1.3.0 in Distributed Management Task Force (DMTF).

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __PLDM_H__
#define __PLDM_H__

#pragma pack(1)

typedef struct {
  UINT8    InstanceID;
  UINT8    PldmType;
  UINT8    PldmCommandCode;
//UINT8    Payload[];
} PLDM_MESSAGE_HEADER;

typedef struct {
  UINT8    PldmCompletionCode;
} PLDM_MESSAGE_RESPONSE_HEADER;

#define PLDM_BASE_CODE_SUCCESS    0
#define PLDM_BASE_CODE_ERROR      1

#define PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY            0x00
#define MCTP_MESSAGE_TYPE_SMBIOS                       0x01
#define MCTP_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL  0x02
#define MCTP_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION   0x03
#define MCTP_MESSAGE_TYPE_FRU_DATA                     0x04
#define MCTP_MESSAGE_TYPE_FIRMWARE_UPDATE              0x05
#define MCTP_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT    0x06
#define MCTP_MESSAGE_TYPE_OEM                          0x3F

//
// PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY
//
#define PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID           0x01
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID           0x02
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION  0x03
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES    0x04
#define PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS 0x05

#pragma pack()

#endif
