/** @file
  SPDM common library.
  It follows the SPDM Specification.

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderLibInternal.h"

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
  //UINT8 ReservedFlag1 = (UINT8)(CapabilitiesFlag)&0x01;
  UINT8 CERT_CAP = (UINT8)(CapabilitiesFlag>>1)&0x01;
  //UINT8 CHAL_CAP = (UINT8)(CapabilitiesFlag>>2)&0x01;
  UINT8 MEAS_CAP = (UINT8)(CapabilitiesFlag>>3)&0x03;
  UINT8 MEAS_FRESH_CAP = (UINT8)(CapabilitiesFlag>>5)&0x01;
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
      //MEAS_CAP shall be set to 00b
      if(MEAS_CAP!=0){
        return FALSE;
      }
      //MEAS_FRESH_CAP shall be set to 0b
      if(MEAS_FRESH_CAP!=0){
        return FALSE;
      }
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
      if(PSK_CAP == 2 || PSK_CAP == 3){
        return FALSE;
      }
    }
      return TRUE;

    default:
      return TRUE;
  }
}

/**
  Process the SPDM GET_CAPABILITIES request and return the response.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestSize                  Size in bytes of the request data.
  @param  Request                      A pointer to the request data.
  @param  ResponseSize                 Size in bytes of the response data.
                                       On input, it means the size in bytes of response data buffer.
                                       On output, it means the size in bytes of copied response data buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired response data buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  Response                     A pointer to the response data.

  @retval RETURN_SUCCESS               The request is processed and the response is returned.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetResponseCapability (
  IN     VOID                 *Context,
  IN     UINTN                RequestSize,
  IN     VOID                 *Request,
  IN OUT UINTN                *ResponseSize,
     OUT VOID                 *Response
  )
{
  SPDM_GET_CAPABILITIES_REQUEST  *SpdmRequest;
  UINTN                          SpdmRequestSize;
  SPDM_CAPABILITIES_RESPONSE     *SpdmResponse;
  SPDM_DEVICE_CONTEXT            *SpdmContext;

  SpdmContext = Context;
  SpdmRequest = Request;

  if (SpdmContext->ResponseState != SpdmResponseStateNormal) {
    return SpdmResponderHandleResponseState(SpdmContext, SpdmRequest->Header.RequestResponseCode, ResponseSize, Response);
  }
  if (SpdmContext->ConnectionInfo.ConnectionState != SpdmConnectionStateAfterVersion) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_UNEXPECTED_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    if (RequestSize != sizeof(SPDM_GET_CAPABILITIES_REQUEST)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  } else {
    if (RequestSize != sizeof(SPDM_MESSAGE_HEADER)) {
      SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
      return RETURN_SUCCESS;
    }
  }

  if (!SpdmCheckFlagCompability(SpdmRequest->Flags,SpdmRequest->Header.SPDMVersion)) {
    SpdmGenerateErrorResponse (SpdmContext, SPDM_ERROR_CODE_INVALID_REQUEST, 0, ResponseSize, Response);
    return RETURN_SUCCESS;
  }
  SpdmRequestSize = RequestSize;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmRequest, SpdmRequestSize);

  ASSERT (*ResponseSize >= sizeof(SPDM_CAPABILITIES_RESPONSE));
  *ResponseSize = sizeof(SPDM_CAPABILITIES_RESPONSE);
  ZeroMem (Response, *ResponseSize);
  SpdmResponse = Response;

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmResponse->Header.RequestResponseCode = SPDM_CAPABILITIES;
  SpdmResponse->Header.Param1 = 0;
  SpdmResponse->Header.Param2 = 0;
  SpdmResponse->CTExponent = SpdmContext->LocalContext.Capability.CTExponent;
  SpdmResponse->Flags = SpdmContext->LocalContext.Capability.Flags;
  //
  // Cache
  //
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, SpdmResponse, *ResponseSize);

  if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    SpdmContext->ConnectionInfo.Capability.CTExponent = SpdmRequest->CTExponent;
    SpdmContext->ConnectionInfo.Capability.Flags = SpdmRequest->Flags;
  } else {
    SpdmContext->ConnectionInfo.Capability.CTExponent = 0;
    SpdmContext->ConnectionInfo.Capability.Flags = 0;
  }
  SpdmSetConnectionState (SpdmContext, SpdmConnectionStateAfterCapabilities);

  return RETURN_SUCCESS;
}
