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

/**
  This function sends GET_MEASUREMENT
  to get measurement from the device.

  If the signature is requested, this function verifies the signature of the measurement.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    Indicates if it is a secured message protected via SPDM session.
                                       If SessionId is NULL, it is a normal message.
                                       If SessionId is NOT NULL, it is a secured message.
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
TrySpdmGetMeasurement (
  IN     VOID                 *Context,
  IN     UINT32               *SessionId,
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
  SPDM_MEASUREMENT_BLOCK_COMMON_HEADER      *MeasurementBlockHeader;
  UINT32                                    MeasurementBlockSize;
  UINT8                                     MeasurementBlockCount;
  UINT8                                     *Ptr;
  VOID                                      *ServerNonce;
  UINT16                                    OpaqueLength;
  VOID                                      *Opaque;
  VOID                                      *Signature;
  UINTN                                     SignatureSize;
  SPDM_DEVICE_CONTEXT                       *SpdmContext;
  SPDM_SESSION_INFO                         *SessionInfo;
  SPDM_SESSION_STATE                        SessionState;

  SpdmContext = Context;
  if (!SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP)) {
    return RETURN_UNSUPPORTED;
  }
  if (SessionId == NULL) {
    if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateAuthenticated) {
      return RETURN_UNSUPPORTED;
    }
  } else {
    if (SpdmContext->ConnectionInfo.ConnectionState < SpdmConnectionStateNegotiated) {
      return RETURN_UNSUPPORTED;
    }
    SessionInfo = SpdmGetSessionInfoViaSessionId (SpdmContext, *SessionId);
    if (SessionInfo == NULL) {
      ASSERT (FALSE);
      return RETURN_UNSUPPORTED;
    }
    SessionState = SpdmSecuredMessageGetSessionState (SessionInfo->SecuredMessageContext);
    if (SessionState != SpdmSessionStateEstablished) {
      return RETURN_UNSUPPORTED;
    }
  }

  if ((SlotIdParam >= MAX_SPDM_SLOT_COUNT) && (SlotIdParam != 0xF)) {
    return RETURN_INVALID_PARAMETER;
  }
  if ((SlotIdParam == 0xF) && (SpdmContext->LocalContext.PeerCertChainProvisionSize == 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  SpdmContext->ErrorState = SPDM_STATUS_ERROR_DEVICE_NO_CAPABILITIES;

  if (SpdmIsCapabilitiesFlagSupported(SpdmContext, TRUE, 0, SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG) &&
      (RequestAttribute != 0)) {
    return RETURN_INVALID_PARAMETER;
  }

  if (RequestAttribute == SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) {
    SignatureSize = GetSpdmAsymSignatureSize (SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo);
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
  Status = SpdmSendSpdmRequest (SpdmContext, SessionId, SpdmRequestSize, &SpdmRequest);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }

  //
  // Cache data
  //
  Status = SpdmAppendMessageM (SpdmContext, &SpdmRequest, SpdmRequestSize);
  if (RETURN_ERROR(Status)) {
    return RETURN_SECURITY_VIOLATION;
  }

  SpdmResponseSize = sizeof(SpdmResponse);
  ZeroMem (&SpdmResponse, sizeof(SpdmResponse));
  Status = SpdmReceiveSpdmResponse (SpdmContext, SessionId, &SpdmResponseSize, &SpdmResponse);
  if (RETURN_ERROR(Status)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponse.Header.RequestResponseCode == SPDM_ERROR) {
    Status = SpdmHandleErrorResponseMain(SpdmContext, SessionId, &SpdmContext->Transcript.MessageM, SpdmRequestSize, &SpdmResponseSize, &SpdmResponse, SPDM_GET_MEASUREMENTS, SPDM_MEASUREMENTS, sizeof(SPDM_MEASUREMENTS_RESPONSE_MAX));
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  } else if (SpdmResponse.Header.RequestResponseCode != SPDM_MEASUREMENTS) {
    ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE)) {
    return RETURN_DEVICE_ERROR;
  }
  if (SpdmResponseSize > sizeof(SpdmResponse)) {
    return RETURN_DEVICE_ERROR;
  }

  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
    if (SpdmResponse.NumberOfBlocks != 0) {
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
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
  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
    if (MeasurementRecordDataLength != 0) {
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
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
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_DEVICE_ERROR;
    }
    if (SpdmIsVersionSupported (SpdmContext, SPDM_MESSAGE_VERSION_11) && SpdmResponse.Header.Param2 != SlotIdParam) {
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr = MeasurementRecordData + MeasurementRecordDataLength;
    ServerNonce = Ptr;
    DEBUG((DEBUG_INFO, "ServerNonce (0x%x) - ", SPDM_NONCE_SIZE));
    InternalDumpData (ServerNonce, SPDM_NONCE_SIZE);
    DEBUG((DEBUG_INFO, "\n"));
    Ptr += SPDM_NONCE_SIZE;

    OpaqueLength = *(UINT16 *)Ptr;
    if (OpaqueLength > MAX_SPDM_OPAQUE_DATA_SIZE) {
      return RETURN_SECURITY_VIOLATION;
    }
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
    Status = SpdmAppendMessageM (SpdmContext, &SpdmResponse, SpdmResponseSize - SignatureSize);
    if (RETURN_ERROR(Status)) {
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SECURITY_VIOLATION;
    }

    Opaque = Ptr;
    Ptr += OpaqueLength;
    DEBUG((DEBUG_INFO, "Opaque (0x%x):\n", OpaqueLength));
    InternalDumpHex (Opaque, OpaqueLength);

    Signature = Ptr;
    DEBUG((DEBUG_INFO, "Signature (0x%x):\n", SignatureSize));
    InternalDumpHex (Signature, SignatureSize);

    Result = SpdmVerifyMeasurementSignature (SpdmContext, Signature, SignatureSize);
    if (!Result) {
      SpdmContext->ErrorState = SPDM_STATUS_ERROR_MEASUREMENT_AUTH_FAILURE;
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SECURITY_VIOLATION;
    }

    ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
  } else {
    //
    // Nonce is absent if there is not signature
    //
    if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                           MeasurementRecordDataLength +
                           sizeof(UINT16)) {
      return RETURN_DEVICE_ERROR;
    }
    Ptr = MeasurementRecordData + MeasurementRecordDataLength;

    OpaqueLength = *(UINT16 *)Ptr;
    if (OpaqueLength > MAX_SPDM_OPAQUE_DATA_SIZE) {
      return RETURN_SECURITY_VIOLATION;
    }
    Ptr += sizeof(UINT16);

    if (SpdmResponseSize < sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                           MeasurementRecordDataLength +
                           sizeof(UINT16) +
                           OpaqueLength) {
      return RETURN_DEVICE_ERROR;
    }
    SpdmResponseSize = sizeof(SPDM_MEASUREMENTS_RESPONSE) +
                       MeasurementRecordDataLength +
                       sizeof(UINT16) +
                       OpaqueLength;
    Status = SpdmAppendMessageM (SpdmContext, &SpdmResponse, SpdmResponseSize);
    if (RETURN_ERROR(Status)) {
      ResetManagedBuffer (&SpdmContext->Transcript.MessageM);
      return RETURN_SECURITY_VIOLATION;
    }
  }

  if (MeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
    *NumberOfBlocks = SpdmResponse.Header.Param1;
    if (*NumberOfBlocks == 0xFF) {
      // the number of block cannot be 0xFF, because index 0xFF will brings confusing.
      return RETURN_DEVICE_ERROR;
    }
    if (*NumberOfBlocks == 0x0) {
      // the number of block cannot be 0x0, because a responder without measurement should clear capability flags.
      return RETURN_DEVICE_ERROR;
    }
  } else {
    *NumberOfBlocks = SpdmResponse.NumberOfBlocks;
    if (*MeasurementRecordLength < MeasurementRecordDataLength) {
      return RETURN_BUFFER_TOO_SMALL;
    }
    if (MeasurementRecordDataLength < sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER)) {
      return RETURN_DEVICE_ERROR;
    }

    MeasurementBlockSize = 0;
    MeasurementBlockCount = 1;
    while (MeasurementBlockSize < MeasurementRecordDataLength) {
      MeasurementBlockHeader = (SPDM_MEASUREMENT_BLOCK_COMMON_HEADER*) &MeasurementRecordData[MeasurementBlockSize];
      if (MeasurementBlockHeader->MeasurementSize > MeasurementRecordDataLength - ((UINT8 *)MeasurementBlockHeader - (UINT8 *)MeasurementRecordData)) {
        return RETURN_DEVICE_ERROR;
      }
      if (MeasurementBlockHeader->MeasurementSpecification == 0 || (MeasurementBlockHeader->MeasurementSpecification & (MeasurementBlockHeader->MeasurementSpecification-1))) {
        return RETURN_DEVICE_ERROR;
      }
      if (MeasurementBlockHeader->MeasurementSpecification != SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec) {
        return RETURN_DEVICE_ERROR;
      }
      if (MeasurementBlockHeader->Index == 0 || MeasurementBlockHeader->Index > *NumberOfBlocks) {
        return RETURN_DEVICE_ERROR;
      }
      if (MeasurementBlockCount > *NumberOfBlocks) {
        return RETURN_DEVICE_ERROR;
      }
      MeasurementBlockCount++;
      MeasurementBlockSize = (UINT32) (MeasurementBlockSize + sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER) + MeasurementBlockHeader->MeasurementSize);
    }

    *MeasurementRecordLength = MeasurementRecordDataLength;
    CopyMem (MeasurementRecord, MeasurementRecordData, MeasurementRecordDataLength);
  }

  SpdmContext->ErrorState = SPDM_STATUS_SUCCESS;
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SpdmGetMeasurement (
  IN     VOID                 *Context,
  IN     UINT32               *SessionId,
  IN     UINT8                RequestAttribute,
  IN     UINT8                MeasurementOperation,
  IN     UINT8                SlotIdParam,
     OUT UINT8                *NumberOfBlocks,
  IN OUT UINT32               *MeasurementRecordLength,
     OUT VOID                 *MeasurementRecord
  )
{
  SPDM_DEVICE_CONTEXT    *SpdmContext;
  UINTN                   Retry;
  RETURN_STATUS           Status;

  SpdmContext = Context;
  Retry = SpdmContext->RetryTimes;
  do {
    Status = TrySpdmGetMeasurement(SpdmContext, SessionId, RequestAttribute, MeasurementOperation, SlotIdParam, NumberOfBlocks, MeasurementRecordLength, MeasurementRecord);
    if (RETURN_NO_RESPONSE != Status) {
      return Status;
    }
  } while (Retry-- != 0);

  return Status;
}

