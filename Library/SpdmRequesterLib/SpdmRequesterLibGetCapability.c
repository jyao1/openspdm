/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"
#include <stdio.h>

/**
  This function checks the compability of the received CAPABILITES flag.
  Some flags are mutually inclusive/exclusive.

  @param  CapabilitiesFlag             The received CAPABILITIES Flag.
  @param  Version                      The SPMD message version.


  @retval True                         The received Capabilities flag is valid.
  @retval False                        The received Capabilities flag is invalid.
**/
BOOLEAN
SpdmCheckFlagCompability (
  IN UINT32 CapabilitiesFlag,
  IN UINT8  Version
)
{
  //UINT8 CACHE_CAP = (UINT8)(CapabilitiesFlag)&0x01;
  UINT8 CERT_CAP = (UINT8)(CapabilitiesFlag>>1)&0x01;
  //UINT8 CHAL_CAP = (UINT8)(CapabilitiesFlag>>2)&0x01;
  UINT8 MEAS_CAP = (UINT8)(CapabilitiesFlag>>3)&0x03;
  //UINT8 MEAS_FRESH_CAP = (UINT8)(CapabilitiesFlag>>5)&0x01;
  UINT8 ENCRYPT_CAP = (UINT8)(CapabilitiesFlag>>6)&0x01;
  UINT8 MAC_CAP = (UINT8)(CapabilitiesFlag>>7)&0x01;
  UINT8 MUT_AUTH_CAP = (UINT8)(CapabilitiesFlag>>8)&0x01;
  UINT8 KEY_EX_CAP = (UINT8)(CapabilitiesFlag>>9)&0x01;
  UINT8 PSK_CAP = (UINT8)(CapabilitiesFlag>>10)&0x03;
  UINT8 ENCAP_CAP = (UINT8)(CapabilitiesFlag>>12)&0x01;
  //UINT8 HBEAT_CAP = (UINT8)(CapabilitiesFlag>>13)&0x01;
  //UINT8 KEY_UPD_CAP = (UINT8)(CapabilitiesFlag>>14)&0x01;
  UINT8 HANDSHAKE_IN_THE_CLEAR_CAP = (UINT8)(CapabilitiesFlag>>15)&0x01;
  UINT8 PUB_KEY_ID_CAP = (UINT8)(CapabilitiesFlag>>16)&0x01;
  //UINT32 ReservedFlags = (UINT32)(CapabilitiesFlag>>17);

  switch (Version) {
    case SPDM_MESSAGE_VERSION_10:
      return TRUE;

    case SPDM_MESSAGE_VERSION_11:
    {
      //Encrypt_cap set and psk_cap+key_ex_cap cleared
      if(ENCRYPT_CAP!=0 && (PSK_CAP==0 && KEY_EX_CAP==0)){
        return FALSE;
      }
      //MAC_cap set and psk_cap+key_ex_cap cleared
      if(MAC_CAP!=0 && (PSK_CAP==0 && KEY_EX_CAP==0)){
        return FALSE;
      }
      //Key_ex_cap set and encrypt_cap+mac_cap cleared
      if(KEY_EX_CAP!=0 && (ENCRYPT_CAP==0 && MAC_CAP==0)){
        return FALSE;
      }
      //PSK_cap set and encrypt_cap+mac_cap cleared
      if(PSK_CAP!=0 && (ENCRYPT_CAP==0 && MAC_CAP==0)){
        return FALSE;
      }
      //Muth_auth_cap set and encap_cap cleared
      if(MUT_AUTH_CAP!=0 && ENCAP_CAP==0){
        return FALSE;
      }
      //Handshake_in_the_clear_cap set and key_ex_cap cleared
      if(HANDSHAKE_IN_THE_CLEAR_CAP!=0 && KEY_EX_CAP==0){
        return FALSE;
      }
      //Handshake_in_the_clear_cap set and encrypt_cap+mac_cap cleared
      if((ENCRYPT_CAP==0 && MAC_CAP==0) && HANDSHAKE_IN_THE_CLEAR_CAP!=0){
        return FALSE;
      }
      //Pub_key_id_cap set and cert_cap set
      if(PUB_KEY_ID_CAP!=0 && CERT_CAP!=0){
        return FALSE;
      }
      //Reserved values selected in Flags
      if(MEAS_CAP == 3 || PSK_CAP == 3){
        return FALSE;
      }
    }
      return TRUE;

    default:
      return TRUE;
  }
}

/**
  This function sends GET_CAPABILITIES and receives CAPABILITIES.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_CAPABILITIES is sent and the CAPABILITIES is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
TrySpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  RETURN_STATUS                             Status;
  SPDM_GET_CAPABILITIES_REQUEST             SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_CAPABILITIES_RESPONSE                SpdmResponse;
  UINTN                                     SpdmResponseSize;

  if (SpdmContext->ConnectionInfo.ConnectionState != SpdmConnectionStateAfterVersion) {
    return RETURN_UNSUPPORTED;
  }

  ZeroMem (&SpdmRequest, sizeof(SpdmRequest));
  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
    SpdmRequestSize = sizeof(SpdmRequest);
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmRequestSize = sizeof(SpdmRequest.Header);
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_CAPABILITIES;
  SpdmRequest.Header.Param1 = 0;
  SpdmRequest.Header.Param2 = 0;
  SpdmRequest.CTExponent = SpdmContext->LocalContext.Capability.CTExponent;
  SpdmRequest.Flags = SpdmContext->LocalContext.Capability.Flags;
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  Status = SpdmAppendMessageA (SpdmContext, &SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    ShrinkManagedBuffer(&SpdmContext->Transcript.MessageA, SpdmRequestSize);
    Status = SpdmHandleSimpleErrorResponse(SpdmContext, SpdmResponse.Header.Param1);
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_CAPABILITIES) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_CAPABILITIES_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }
  //Check if received message version matches sent message version
  if (SpdmRequest.Header.SPDMVersion != SpdmResponse.Header.SPDMVersion) {
    return RETURN_DEVICE_ERROR;
  }
  SpdmResponseSize = sizeof(SPDM_CAPABILITIES_RESPONSE);

  if(!SpdmCheckFlagCompability(SpdmResponse.Flags,SpdmResponse.Header.SPDMVersion)){
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  Status = SpdmAppendMessageA (SpdmContext, &SpdmResponse, SpdmResponseSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmContext->ConnectionInfo.Capability.CTExponent = SpdmResponse.CTExponent;
  SpdmContext->ConnectionInfo.Capability.Flags = SpdmResponse.Flags;

  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterCapabilities;

  return RETURN_SUCCESS;
}

/**
  This function sends GET_CAPABILITIES and receives CAPABILITIES.

  @param  SpdmContext                  A pointer to the SPDM context.

  @retval RETURN_SUCCESS               The GET_CAPABILITIES is sent and the CAPABILITIES is received.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
**/
RETURN_STATUS
EFIAPI
SpdmGetCapabilities (
  IN     SPDM_DEVICE_CONTEXT  *SpdmContext
  )
{
  UINTN         Retry;
  RETURN_STATUS Status;

  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmGetCapabilities(SpdmContext);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}
