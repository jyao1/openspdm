/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_EMU_NV_STORAGE_LIB_H__
#define __SPDM_EMU_NV_STORAGE_LIB_H__

#include <Base.h>
#include <IndustryStandard/Spdm.h>

#define SPDM_NEGOTIATED_STATE_STRUCT_SIGNATURE  SIGNATURE_32('S', 'P', 'D', 'M')
#define SPDM_NEGOTIATED_STATE_STRUCT_VERSION  1

#pragma pack(1)
typedef struct {
  UINT32               Signature;
  UINT32               Version;
  UINT8                SpdmVersion;
  UINT8                RequesterCapCTExponent;
  UINT32               RequesterCapFlags;
  UINT8                ResponderCapCTExponent;
  UINT32               ResponderCapFlags;
  UINT8                MeasurementSpec;
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymAlgo;
  UINT32               BaseHashAlgo;
  UINT16               DHENamedGroup;
  UINT16               AEADCipherSuite;
  UINT16               ReqBaseAsymAlg;
  UINT16               KeySchedule;
} SPDM_NEGOTIATED_STATE_STRUCT;
#pragma pack()

/**
  Load the NegotiatedState from NV storage to an SPDM context.
*/
RETURN_STATUS
EFIAPI
SpdmLoadNegotiatedState (
  IN VOID                         *SpdmContext,
  IN BOOLEAN                      IsRequester
  );

/**
  Save the NegotiatedState to NV storage from an SPDM context.
*/
RETURN_STATUS
EFIAPI
SpdmSaveNegotiatedState (
  IN VOID                         *SpdmContext,
  IN BOOLEAN                      IsRequester
  );

/**
  Clear the NegotiatedState in the NV storage.
*/
RETURN_STATUS
EFIAPI
SpdmClearNegotiatedState (
  IN VOID                         *SpdmContext
  );

#endif