/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterLibInternal.h"

#pragma pack(1)
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                NumberOfBlocks;
  UINT8                MeasurementRecordLength[3];
  UINT8                MeasurementRecord[(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + MAX_HASH_SIZE) * MAX_SPDM_MEASUREMENT_BLOCK_COUNT];
  UINT8                Nonce[SPDM_NONCE_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
} SPDM_MEASUREMENTS_RESPONSE_MAX;
#pragma pack()

BOOLEAN
SpdmRequesterVerifyMeasurementSignature (
  IN SPDM_DEVICE_CONTEXT          *SpdmContext,
  IN VOID                         *SignData,
  UINTN                           SignDataSize
  )
{
  UINTN                                     HashSize;
  UINT8                                     HashData[MAX_HASH_SIZE];
  BOOLEAN                                   Result;
  UINT8                                     *CertBuffer;
  UINTN                                     CertBufferSize;
  VOID                                      *Context;
  UINT8                                     *CertChainBuffer;
  UINTN                                     CertChainBufferSize;

  HashSize = GetSpdmHashSize (SpdmContext);

  DEBUG((DEBUG_INFO, "L1L2 Data :\n"));
  InternalDumpHex (GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2));

  SpdmHashAll (SpdmContext, GetManagedBuffer(&SpdmContext->Transcript.L1L2), GetManagedBufferSize(&SpdmContext->Transcript.L1L2), HashData);
  DEBUG((DEBUG_INFO, "L1L2 Hash - "));
  InternalDumpData (HashData, HashSize);
  DEBUG((DEBUG_INFO, "\n"));

  if (SpdmContext->ConnectionInfo.PeerCertChainBufferSize == 0) {
    return FALSE;
  }

  CertChainBuffer = (UINT8 *)SpdmContext->ConnectionInfo.PeerCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertChainBufferSize = SpdmContext->ConnectionInfo.PeerCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

  //
  // Get leaf cert from cert chain
  //
  Result = X509GetCertFromCertChain (CertChainBuffer, CertChainBufferSize, -1,  &CertBuffer, &CertBufferSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPublicKeyFromX509 (SpdmContext, CertBuffer, CertBufferSize, &Context);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymVerify (
             SpdmContext,
             Context,
             HashData,
             HashSize,
             SignData,
             SignDataSize
             );
  SpdmAsymFree (SpdmContext, Context);
  if (!Result) {
    DEBUG((DEBUG_INFO, "!!! VerifyMeasurementSignature - FAIL !!!\n"));
    return FALSE;
  }

  DEBUG((DEBUG_INFO, "!!! VerifyMeasurementSignature - PASS !!!\n"));
  return TRUE;
}

/**
  This function sends GET_MEASUREMENT
  to get measurement from the device.

  If the signature is requested, this function verifies the signature of the measurement.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  RequestAttribute             The request attribute of the request message.
  @param  MeasurementOperation         The measurement operation of the request message.
  @param  SlotNum                      The number of slot for the certificate chain.
  @param  NumberOfBlocks               The number of blocks of the measurement record.
  @param  MeasurementRecordLength      On input, indicate the size in bytes of the destination buffer to store the measurement record.
                                       On output, indicate the size in bytes of the measurement record.
  @param  MeasurementRecord            A pointer to a destination buffer to store the measurement record.

  @retval RETURN_SUCCESS               The measurement is got successfully.
  @retval RETURN_DEVICE_ERROR          A device error occurs when communicates with the device.
  @retval RETURN_SECURITY_VIOLATION    Any verification fails.
**/
RETURN_STATUS
EFIAPI
SpdmGetMeasurement (
  IN     VOID                 *Context,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
  IN     UINT8                SlotIdParam,
     OUT UINT8                *NumberOfBlocks,
  IN OUT UINT32               *MeasurementRecordLength,
     OUT VOID                 *MeasurementRecord
  )
{
  BOOLEAN                                   Result;
  RETURN_STATUS                             Status;
  SPDM_GET_MEASUREMENTS_REQUEST             SpdmRequest;
  UINTN                                     SpdmRequestSize;
  SPDM_MEASUREMENTS_RESPONSE_MAX            SpdmResponse;
  UINTN                                     SpdmResponseSize;
  UINT32                                    MeasurementRecordDataLength;
  UINT8                                     *MeasurementRecordData;
  UINT8                                     *Ptr;
  VOID                                      *ServerNonce;
  UINT16                                    OpaqueLength;
  VOID                                      *Opaque;
  VOID                                      *Signature;
  UINTN                                     SignatureSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;

  SpdmContext = Context;
  if (((SpdmContext->SpdmCmdReceiveState & SPDM_NEGOTIATE_ALGORITHMS_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CAPABILITIES_RECEIVE_FLAG) == 0) ||
      ((SpdmContext->SpdmCmdReceiveState & SPDM_GET_CERTIFICATE_RECEIVE_FLAG) == 0)) {
    return RETURN_DEVICE_ERROR;
  }
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) {
    return RETURN_DEVICE_ERROR;
  }

  if ((SlotIdParam >= MAX_SPDM_SLOT_COUNT) && (SlotIdParam != 0xF)) {
    return RETURN_INVALID_PARAMETER;
  }
  if ((SlotIdParam == 0xF) && (SpdmContext->LocalContext.PeerCertChainProvisionSize == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) {
    RequestAttribute = 0;
  }

  if (RequestAttribute == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    SignatureSize = GetSpdmAsymSize (SpdmContext);
  } else {
    SignatureSize = 0;
  }

  if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_11;
  } else {
    SpdmRequest.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
  }
  SpdmRequest.Header.RequestResponseCode = SPDM_GET_MEASUREMENTS;
  SpdmRequest.Header.Param1 = RequestAttribute;
  SpdmRequest.Header.Param2 = MeasurementOperation;
  if (RequestAttribute == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11)) {
      SpdmRequestSize = sizeof(SpdmRequest);
    } else {
      SpdmRequestSize = sizeof(SpdmRequest) - sizeof(SpdmRequest.SlotIDParam);
    }

    SpdmGetRandomNumber (SPDM_NONCE_SIZE, SpdmRequest.Nonce);
    DEBUG((DEBUG_INFO, "ClientNonce - "));
    InternalDumpData (SpdmRequest.Nonce, SPDM_NONCE_SIZE);
    DEBUG((DEBUG_INFO, "\n"));
    SpdmRequest.SlotIDParam = SlotIdParam;
  } else {
    SpdmRequestSize = sizeof(SpdmRequest.Header);
  }
  Status = SpdmSendSpdmRequest (SpdmContext, NULL, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  ResetManagedBuffer (&SpdmContext->Transcript.M1M2);
  AppendManagedBuffer (&SpdmContext->Transcript.L1L2, &SpdmRequest, SpdmRequestSize);

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, NULL, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode != SPDM_MEASUREMENTS) {
    return RETURN_DEVICE_ERROR;
  }

  if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }

  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS) {
    if (SpdmResponse.NumberOfBlocks != 0) {
      return RETURN_DEVICE_ERROR;
    }
  } else if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS) {
    if (SpdmResponse.NumberOfBlocks == 0) {
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (SpdmResponse.NumberOfBlocks != 1) {
      return RETURN_DEVICE_ERROR;
    }
  }

  MeasurementRecordDataLength = SpdmReadUint24 (SpdmResponse.MeasurementRecordLength);
  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS) {
    if (MeasurementRecordDataLength != 0) {
      return RETURN_DEVICE_ERROR;
    }
  } else {
    if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurementRecordDataLength) {
      return RETURN_DEVICE_ERROR;
    }
    if (MeasurementRecordDataLength >= sizeof(SpdmResponse.MeasurementRecord)) {
      return RETURN_DEVICE_ERROR;
    }
    DEBUG((DEBUG_INFO, "MeasurementRecordLength - 0x%06x\n", MeasurementRecordDataLength));
  }

  MeasurementRecordData = SpdmResponse.MeasurementRecord;

  if (RequestAttribute == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                           MeasurementRecordDataLength +
                           SPDM_NONCE_SIZE +
                           sizeof(UINT16)) {
      return RETURN_DEVICE_ERROR;
    }
    Ptr = MeasurementRecordData + MeasurementRecordDataLength;
    ServerNonce = Ptr;
    DEBUG((DEBUG_INFO, "ServerNonce (0x%x) - ", SPDM_NONCE_SIZE));
    InternalDumpData (ServerNonce, SPDM_NONCE_SIZE);
    DEBUG((DEBUG_INFO, "\n"));
    Ptr += SPDM_NONCE_SIZE;

    OpaqueLength = *(UINT16 *)Ptr;
    Ptr += sizeof(UINT16);

    if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                           MeasurementRecordDataLength +
                           SPDM_NONCE_SIZE +
                           sizeof(UINT16) +
                           OpaqueLength +
                           SignatureSize) {
      return RETURN_DEVICE_ERROR;
    }
    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                       MeasurementRecordDataLength +
                       SPDM_NONCE_SIZE +
                       sizeof(UINT16) +
                       OpaqueLength +
                       SignatureSize;
    AppendManagedBuffer (&SpdmContext->Transcript.L1L2, &SpdmResponse, SpdmResponseSize - SignatureSize);

    Opaque = Ptr;
    Ptr += OpaqueLength;
    DEBUG((DEBUG_INFO, "Opaque (0x%x):\n", OpaqueLength));
    InternalDumpHex (Opaque, OpaqueLength);

    Signature = Ptr;
    DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
    InternalDumpHex (Signature, SignatureSize);

    Result = SpdmRequesterVerifyMeasurementSignature (SpdmContext, Signature, SignatureSize);
    if (!Result) {
      SpdmContext->ErrorState = SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE;
      return RETURN_SECURITY_VIOLATION;
    }

    ResetManagedBuffer (&SpdmContext->Transcript.L1L2);
  } else {
    if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS) {
      SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
    } else {
      SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurementRecordDataLength;
    }
    AppendManagedBuffer (&SpdmContext->Transcript.L1L2, &SpdmResponse, SpdmResponseSize);
  }

  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS) {
    *NumberOfBlocks = SpdmResponse.Header.Param1;
  } else {
    *NumberOfBlocks = SpdmResponse.NumberOfBlocks;
    if (*MeasurementRecordLength < MeasurementRecordDataLength) {
      return RETURN_BUFFER_TOO_SMALL;
    }
    *MeasurementRecordLength = MeasurementRecordDataLength;
    CopyMem (MeasurementRecord, MeasurementRecordData, MeasurementRecordDataLength);
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_MEASUREMENTS_RECEIVE_FLAG;
  return RETURN_SUCCESS;
}
