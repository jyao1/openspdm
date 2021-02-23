/** @file
  SPDM common library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include "SpdmDeviceSecretLibInternal.h"

BOOLEAN
ReadResponderPrivateCertificate (
  IN  UINT32  BaseAsymAlgo,
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  CHAR8    *File;

  switch (BaseAsymAlgo) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_responder.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_responder.key";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, Data, Size);
  return Res;
}

BOOLEAN
ReadRequesterPrivateCertificate (
  IN  UINT16  ReqBaseAsymAlg,
  OUT VOID    **Data,
  OUT UINTN   *Size
  )
{
  BOOLEAN  Res;
  CHAR8    *File;

  switch (ReqBaseAsymAlg) {
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048:
    File = "Rsa2048/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072:
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072:
    File = "Rsa3072/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256:
    File = "EcP256/end_requester.key";
    break;
  case SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384:
    File = "EcP384/end_requester.key";
    break;
  default:
    ASSERT( FALSE);
    return FALSE;
  }
  Res = ReadInputFile (File, Data, Size);
  return Res;
}

/**
  Collect the device measurement.

  @param  MeasurementSpecification     Indicates the measurement specification.
                                       It must align with MeasurementSpecification (SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_*)
  @param  MeasurementHashAlgo          Indicates the measurement hash algorithm.
                                       It must align with MeasurementHashAlgo (SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_*)
  @param  DeviceMeasurementCount       The count of the device measurement block.
  @param  DeviceMeasurement            A pointer to a destination buffer to store the concatenation of all device measurement blocks.
  @param  DeviceMeasurementSize        On input, indicates the size in bytes of the destination buffer.
                                       On output, indicates the size in bytes of all device measurement blocks in the buffer.

  @retval TRUE  the device measurement collection success and measurement is returned.
  @retval FALSE the device measurement collection fail.
**/
BOOLEAN
EFIAPI
SpdmMeasurementCollectionFunc (
  IN      UINT8        MeasurementSpecification,
  IN      UINT32       MeasurementHashAlgo,
     OUT  UINT8        *DeviceMeasurementCount,
     OUT  VOID         *DeviceMeasurement,
  IN OUT  UINTN        *DeviceMeasurementSize
  )
{
  SPDM_MEASUREMENT_BLOCK_DMTF  *MeasurementBlock;
  UINTN                        HashSize;
  UINT8                        Index;
  UINT8                        Data[MEASUREMENT_MANIFEST_SIZE];
  UINTN                        TotalSize;

  ASSERT (MeasurementSpecification == SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF);
  if (MeasurementSpecification != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
    return FALSE;
  }

  HashSize = GetSpdmMeasurementHashSize (MeasurementHashAlgo);
  ASSERT (HashSize != 0);

  *DeviceMeasurementCount = MEASUREMENT_BLOCK_NUMBER;
  if (HashSize != 0xFFFFFFFF) {
    TotalSize = (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize) +
                           (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + sizeof(Data));
  } else {
    TotalSize = (MEASUREMENT_BLOCK_NUMBER - 1) * (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + sizeof(Data)) +
                           (sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + sizeof(Data));
  }
  ASSERT (*DeviceMeasurementSize >= TotalSize);
  *DeviceMeasurementSize = TotalSize;

  MeasurementBlock = DeviceMeasurement;
  for (Index = 0; Index < MEASUREMENT_BLOCK_NUMBER; Index++) {
    MeasurementBlock->MeasurementBlockCommonHeader.Index = Index + 1;
    MeasurementBlock->MeasurementBlockCommonHeader.MeasurementSpecification = SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF;
    if ((Index < 4) && (HashSize != 0xFFFFFFFF)) {
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = Index;
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize = (UINT16)HashSize;
    } else {
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType = Index | SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM;
      MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize = (UINT16)sizeof(Data);
    }
    MeasurementBlock->MeasurementBlockCommonHeader.MeasurementSize = (UINT16)(sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER) + 
                                                                     MeasurementBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize);
    SetMem (Data, sizeof(Data), (UINT8)(Index + 1));
    if ((Index < 4) && (HashSize != 0xFFFFFFFF)) {
      SpdmMeasurementHashAll (MeasurementHashAlgo, Data, sizeof(Data), (VOID *)(MeasurementBlock + 1));
      MeasurementBlock = (VOID *)((UINT8 *)MeasurementBlock + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + HashSize);
    } else {
      CopyMem ((VOID *)(MeasurementBlock + 1), Data, sizeof(Data));
      MeasurementBlock = (VOID *)((UINT8 *)MeasurementBlock + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) + sizeof(Data));
    }
  }

  return TRUE;
}

/**
  Sign an SPDM message data.

  @param  ReqBaseAsymAlg               Indicates the signing algorithm.
  @param  BaseHashAlgo                 Indicates the hash algorithm.
  @param  Message                      A pointer to a message to be signed (before hash).
  @param  MessageSize                  The size in bytes of the message to be signed.
  @param  Signature                    A pointer to a destination buffer to store the signature.
  @param  SigSize                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
BOOLEAN
EFIAPI
SpdmRequesterDataSignFunc (
  IN      UINT16       ReqBaseAsymAlg,
  IN      UINT32       BaseHashAlgo,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  VOID                          *Context;
  VOID                          *PrivatePem;
  UINTN                         PrivatePemSize;
  BOOLEAN                       Result;

  Result = ReadRequesterPrivateCertificate (ReqBaseAsymAlg, &PrivatePem, &PrivatePemSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmReqAsymGetPrivateKeyFromPem (ReqBaseAsymAlg, PrivatePem, PrivatePemSize, NULL, &Context);
  if (!Result) {
    return FALSE;
  }
  Result = SpdmReqAsymSign (
             ReqBaseAsymAlg,
             BaseHashAlgo,
             Context,
             Message,
             MessageSize,
             Signature,
             SigSize
             );
  SpdmReqAsymFree (ReqBaseAsymAlg, Context);
  free (PrivatePem);

  return Result;
}

/**
  Sign an SPDM message data.

  @param  BaseAsymAlgo                 Indicates the signing algorithm.
  @param  BaseHashAlgo                 Indicates the hash algorithm.
  @param  Message                      A pointer to a message to be signed (before hash).
  @param  MessageSize                  The size in bytes of the message to be signed.
  @param  Signature                    A pointer to a destination buffer to store the signature.
  @param  SigSize                      On input, indicates the size in bytes of the destination buffer to store the signature.
                                       On output, indicates the size in bytes of the signature in the buffer.

  @retval TRUE  signing success.
  @retval FALSE signing fail.
**/
BOOLEAN
EFIAPI
SpdmResponderDataSignFunc (
  IN      UINT32       BaseAsymAlgo,
  IN      UINT32       BaseHashAlgo,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  VOID                          *Context;
  VOID                          *PrivatePem;
  UINTN                         PrivatePemSize;
  BOOLEAN                       Result;

  Result = ReadResponderPrivateCertificate (BaseAsymAlgo, &PrivatePem, &PrivatePemSize);
  if (!Result) {
    return FALSE;
  }

  Result = SpdmAsymGetPrivateKeyFromPem (BaseAsymAlgo, PrivatePem, PrivatePemSize, NULL, &Context);
  if (!Result) {
    return FALSE;
  }
  Result = SpdmAsymSign (
             BaseAsymAlgo,
             BaseHashAlgo,
             Context,
             Message,
             MessageSize,
             Signature,
             SigSize
             );
  SpdmAsymFree (BaseAsymAlgo, Context);
  free (PrivatePem);

  return Result;
}

UINT8  mMyZeroFilledBuffer[64];
UINT8  gBinStr0[0x11] = {
       0x00, 0x00, // Length - To be filled
       0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20, // Version: 'spdm1.1 '
       0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64,       // label: 'derived'
       };

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  BaseHashAlgo                 Indicates the hash algorithm.
  @param  PskHint                      Pointer to the user-supplied PSK Hint.
  @param  PskHintSize                  PSK Hint size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
BOOLEAN
EFIAPI
SpdmPskHandshakeSecretHkdfExpandFunc (
  IN      UINT32       BaseHashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  )
{
  VOID                          *Psk;
  UINTN                         PskSize;
  UINTN                         HashSize;
  BOOLEAN                       Result;
  UINT8                         HandshakeSecret[64];

  if ((PskHint == NULL) && (PskHintSize == 0)) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else if ((PskHint != NULL) && (PskHintSize != 0) &&
             (strcmp((const char *)PskHint, TEST_PSK_HINT_STRING) == 0) &&
             (PskHintSize == sizeof(TEST_PSK_HINT_STRING))) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else {
    return FALSE;
  }
  printf ("[PSK]: ");
  DumpHexStr (Psk, PskSize);
  printf ("\n");

  HashSize = GetSpdmHashSize (BaseHashAlgo);

  Result = SpdmHmacAll (BaseHashAlgo, mMyZeroFilledBuffer, HashSize, Psk, PskSize, HandshakeSecret);
  if (!Result) {
    return Result;
  }

  Result = SpdmHkdfExpand (BaseHashAlgo, HandshakeSecret, HashSize, Info, InfoSize, Out, OutSize);
  ZeroMem (HandshakeSecret, HashSize);

  return Result;
}

/**
  Derive HMAC-based Expand Key Derivation Function (HKDF) Expand, based upon the negotiated HKDF algorithm.

  @param  BaseHashAlgo                 Indicates the hash algorithm.
  @param  PskHint                      Pointer to the user-supplied PSK Hint.
  @param  PskHintSize                  PSK Hint size in bytes.
  @param  Info                         Pointer to the application specific info.
  @param  InfoSize                     Info size in bytes.
  @param  Out                          Pointer to buffer to receive hkdf value.
  @param  OutSize                      Size of hkdf bytes to generate.

  @retval TRUE   Hkdf generated successfully.
  @retval FALSE  Hkdf generation failed.
**/
BOOLEAN
EFIAPI
SpdmPskMasterSecretHkdfExpandFunc (
  IN      UINT32       BaseHashAlgo,
  IN      CONST UINT8  *PskHint, OPTIONAL
  IN      UINTN        PskHintSize, OPTIONAL
  IN      CONST UINT8  *Info,
  IN      UINTN        InfoSize,
     OUT  UINT8        *Out,
  IN      UINTN        OutSize
  )
{
  VOID                          *Psk;
  UINTN                         PskSize;
  UINTN                         HashSize;
  BOOLEAN                       Result;
  UINT8                         HandshakeSecret[64];
  UINT8                         Salt1[64];
  UINT8                         MasterSecret[64];

  if ((PskHint == NULL) && (PskHintSize == 0)) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else if ((PskHint != NULL) && (PskHintSize != 0) &&
             (strcmp((const char *)PskHint, TEST_PSK_HINT_STRING) == 0) &&
             (PskHintSize == sizeof(TEST_PSK_HINT_STRING))) {
    Psk = TEST_PSK_DATA_STRING;
    PskSize = sizeof(TEST_PSK_DATA_STRING);
  } else {
    return FALSE;
  }

  HashSize = GetSpdmHashSize (BaseHashAlgo);

  Result = SpdmHmacAll (BaseHashAlgo, mMyZeroFilledBuffer, HashSize, Psk, PskSize, HandshakeSecret);
  if (!Result) {
    return Result;
  }

  *(UINT16 *)gBinStr0 = (UINT16)HashSize;
  Result = SpdmHkdfExpand (BaseHashAlgo, HandshakeSecret, HashSize, gBinStr0, sizeof(gBinStr0), Salt1, HashSize);
  ZeroMem (HandshakeSecret, HashSize);
  if (!Result) {
    return Result;
  }

  Result = SpdmHmacAll (BaseHashAlgo, mMyZeroFilledBuffer, HashSize, Salt1, HashSize, MasterSecret);
  ZeroMem (Salt1, HashSize);
  if (!Result) {
    return Result;
  }

  Result = SpdmHkdfExpand (BaseHashAlgo, MasterSecret, HashSize, Info, InfoSize, Out, OutSize);
  ZeroMem (MasterSecret, HashSize);

  return Result;
}

