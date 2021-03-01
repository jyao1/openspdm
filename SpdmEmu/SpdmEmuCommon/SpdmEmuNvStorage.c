/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmEmu.h"

CHAR8 *mLoadStateFileName;
CHAR8 *mSaveStateFileName;
UINT8  mEndSessionAttributes = SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;

/**
  Load the NegotiatedState from NV storage to an SPDM context.
*/
RETURN_STATUS
EFIAPI
SpdmLoadNegotiatedState (
  IN VOID                         *SpdmContext,
  IN BOOLEAN                      IsRequester
  )
{
  BOOLEAN                      Ret;
  VOID                         *FileData;
  UINTN                        FileSize;
  SPDM_NEGOTIATED_STATE_STRUCT NegotiatedState;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  SPDM_VERSION_NUMBER          SpdmVersion;

  if (mLoadStateFileName == NULL) {
    return RETURN_UNSUPPORTED;
  }
  Ret = ReadInputFile (mLoadStateFileName, &FileData, &FileSize);
  if (!Ret) {
    printf ("LoadState fail - read file error\n");
    return RETURN_DEVICE_ERROR;
  }

  if (FileSize != sizeof(NegotiatedState)) {
    printf ("LoadState fail - size mismatch\n");
    free (FileData);
    return RETURN_UNSUPPORTED;
  }

  CopyMem (&NegotiatedState, FileData, FileSize);
  free (FileData);

  if (NegotiatedState.Signature != SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE) {
    printf ("LoadState fail - signature mismatch\n");
    return RETURN_UNSUPPORTED;
  }
  if (NegotiatedState.Version != SPDM_NEGOTIATED_STATE_STRUCT_VERSION) {
    printf ("LoadState fail - version mismatch\n");
    return RETURN_UNSUPPORTED;
  }

  printf ("LoadState from %s\n", mLoadStateFileName);

  //
  // Override local setting
  //
  mUseVersion = NegotiatedState.SpdmVersion;
  mUseRequesterCapabilityFlags = NegotiatedState.RequesterCapFlags;
  mUseResponderCapabilityFlags = NegotiatedState.ResponderCapFlags;
  if (IsRequester) {
    mUseCapabilityFlags = NegotiatedState.RequesterCapFlags;
  } else {
    mUseCapabilityFlags = NegotiatedState.ResponderCapFlags;
  }
  mSupportMeasurementSpec = NegotiatedState.MeasurementSpec;
  mSupportMeasurementHashAlgo = NegotiatedState.MeasurementHashAlgo;
  mSupportAsymAlgo = NegotiatedState.BaseAsymAlgo;
  mSupportHashAlgo = NegotiatedState.BaseHashAlgo;
  mSupportDheAlgo = NegotiatedState.DHENamedGroup;
  mSupportAeadAlgo = NegotiatedState.AEADCipherSuite;
  mSupportReqAsymAlgo = NegotiatedState.ReqBaseAsymAlg;
  mSupportKeyScheduleAlgo = NegotiatedState.KeySchedule;

  //
  // Set connection info
  //
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;

  SpdmVersion.MajorVersion = (mUseVersion >> 4) & 0xF;
  SpdmVersion.MinorVersion = mUseVersion & 0xF;
  SpdmVersion.Alpha = 0;
  SpdmVersion.UpdateVersionNumber = 0;
  SpdmSetData (SpdmContext, SpdmDataSpdmVersion, &Parameter, &SpdmVersion, sizeof(SpdmVersion));

  Data8 = 0;
  SpdmSetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, sizeof(Data8));
  if (IsRequester) {
    Data32 = NegotiatedState.ResponderCapFlags;
  } else {
    Data32 = NegotiatedState.RequesterCapFlags;
  }
  SpdmSetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, sizeof(Data32));

  Data8 = mSupportMeasurementSpec;
  SpdmSetData (SpdmContext, SpdmDataMeasurementSpec, &Parameter, &Data8, sizeof(Data8));
  Data32 = mSupportMeasurementHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = mSupportAsymAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, sizeof(Data32));
  Data32 = mSupportHashAlgo;
  SpdmSetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, sizeof(Data32));
  if (mUseVersion == SPDM_MESSAGE_VERSION_11) {
    Data16 = mSupportDheAlgo;
    SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
    Data16 = mSupportAeadAlgo;
    SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
    Data16 = mSupportReqAsymAlgo;
    SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof(Data16));
    Data16 = mSupportKeyScheduleAlgo;
    SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));
  } else {
    Data16 = 0;
    SpdmSetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, sizeof(Data16));
    Data16 = 0;
    SpdmSetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, sizeof(Data16));
    Data16 = 0;
    SpdmSetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, sizeof(Data16));
    Data16 = 0;
    SpdmSetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, sizeof(Data16));
  }

  //
  // Set connection state finally.
  //
  Data32 = SpdmConnectionStateNegotiated;
  SpdmSetData (SpdmContext, SpdmDataConnectionState, &Parameter, &Data32, sizeof(Data32));

  return RETURN_SUCCESS;
}

/**
  Save the NegotiatedState to NV storage from an SPDM context.
*/
RETURN_STATUS
EFIAPI
SpdmSaveNegotiatedState (
  IN VOID                         *SpdmContext,
  IN BOOLEAN                      IsRequester
  )
{
  BOOLEAN                      Ret;
  SPDM_NEGOTIATED_STATE_STRUCT NegotiatedState;
  UINTN                        DataSize;
  SPDM_DATA_PARAMETER          Parameter;
  UINT8                        Data8;
  UINT16                       Data16;
  UINT32                       Data32;
  SPDM_VERSION_NUMBER          SpdmVersion[MAX_SPDM_VERSION_COUNT];
  UINTN                        Index;

  if (mSaveStateFileName == NULL) {
    return RETURN_UNSUPPORTED;
  }

  mEndSessionAttributes = 0;

  printf ("SaveState to %s\n", mSaveStateFileName);

  ZeroMem (&NegotiatedState, sizeof(NegotiatedState));
  NegotiatedState.Signature = SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE;
  NegotiatedState.Version = SPDM_NEGOTIATED_STATE_STRUCT_VERSION;

  //
  // get setting fron local
  //
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;

  if (IsRequester) {
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, &DataSize);
    NegotiatedState.RequesterCapFlags = Data32;
    DataSize = sizeof(Data8);
    SpdmGetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, &DataSize);
    NegotiatedState.RequesterCapCTExponent = Data8;
  } else {
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, &DataSize);
    NegotiatedState.ResponderCapFlags = Data32;
    DataSize = sizeof(Data8);
    SpdmGetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, &DataSize);
    NegotiatedState.ResponderCapCTExponent = Data8;
  }

  //
  // get setting fron connection
  //
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;

  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataConnectionState, &Parameter, &Data32, &DataSize);
  ASSERT (Data32 == SpdmConnectionStateNegotiated);

  DataSize = sizeof(SpdmVersion);
  ZeroMem (SpdmVersion, sizeof(SpdmVersion));
  SpdmGetData (SpdmContext, SpdmDataSpdmVersion, &Parameter, &SpdmVersion, &DataSize);
  ASSERT (DataSize / sizeof(SPDM_VERSION_NUMBER) > 0);
  Index = DataSize / sizeof(SPDM_VERSION_NUMBER) - 1;
  NegotiatedState.SpdmVersion = (UINT8)((SpdmVersion[Index].MajorVersion << 4) | SpdmVersion[Index].MinorVersion);

  if (IsRequester) {
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, &DataSize);
    NegotiatedState.ResponderCapFlags = Data32;
    DataSize = sizeof(Data8);
    SpdmGetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, &DataSize);
    NegotiatedState.ResponderCapCTExponent = Data8;
  } else {
    DataSize = sizeof(Data32);
    SpdmGetData (SpdmContext, SpdmDataCapabilityFlags, &Parameter, &Data32, &DataSize);
    NegotiatedState.RequesterCapFlags = Data32;
    DataSize = sizeof(Data8);
    SpdmGetData (SpdmContext, SpdmDataCapabilityCTExponent, &Parameter, &Data8, &DataSize);
    NegotiatedState.RequesterCapCTExponent = Data8;
  }

  if ((NegotiatedState.ResponderCapFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP) == 0) {
    printf ("responder has no CACHE_CAP\n");
    return SpdmClearNegotiatedState (SpdmContext);
  }

  DataSize = sizeof(Data8);
  SpdmGetData (SpdmContext, SpdmDataMeasurementSpec, &Parameter, &Data8, &DataSize);
  NegotiatedState.MeasurementSpec = Data8;
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &Data32, &DataSize);
  NegotiatedState.MeasurementHashAlgo = Data32;
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &Data32, &DataSize);
  NegotiatedState.BaseAsymAlgo = Data32;
  DataSize = sizeof(Data32);
  SpdmGetData (SpdmContext, SpdmDataBaseHashAlgo, &Parameter, &Data32, &DataSize);
  NegotiatedState.BaseHashAlgo = Data32;
  DataSize = sizeof(Data16);
  SpdmGetData (SpdmContext, SpdmDataDHENamedGroup, &Parameter, &Data16, &DataSize);
  NegotiatedState.DHENamedGroup = Data16;
  DataSize = sizeof(Data16);
  SpdmGetData (SpdmContext, SpdmDataAEADCipherSuite, &Parameter, &Data16, &DataSize);
  NegotiatedState.AEADCipherSuite = Data16;
  DataSize = sizeof(Data16);
  SpdmGetData (SpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &Data16, &DataSize);
  NegotiatedState.ReqBaseAsymAlg = Data16;
  DataSize = sizeof(Data16);
  SpdmGetData (SpdmContext, SpdmDataKeySchedule, &Parameter, &Data16, &DataSize);
  NegotiatedState.KeySchedule = Data16;

  Ret = WriteOutputFile (mSaveStateFileName, &NegotiatedState, sizeof(NegotiatedState));
  if (!Ret) {
    printf ("SaveState fail - write file error\n");
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}

/**
  Clear the NegotiatedState in the NV storage.
*/
RETURN_STATUS
EFIAPI
SpdmClearNegotiatedState (
  IN VOID                         *SpdmContext
  )
{
  BOOLEAN                      Ret;

  if (mSaveStateFileName == NULL) {
    return RETURN_UNSUPPORTED;
  }

  printf ("ClearState in %s\n", mSaveStateFileName);

  Ret = WriteOutputFile (mSaveStateFileName, NULL, 0);
  if (!Ret) {
    printf ("ClearState fail - write file error\n");
    return RETURN_DEVICE_ERROR;
  }
  return RETURN_SUCCESS;
}
