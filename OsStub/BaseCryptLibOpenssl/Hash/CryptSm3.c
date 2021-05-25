/** @file
  SM3 Digest Wrapper Implementations over openssl.

Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates a new digest context, and then return a reference through the outparam `Sm3CtxPtr`

  If Sm3CtxPtr is NULL, then return FALSE

  @param[out]  Sm3CtxPtr  Pointer to the pointer of the newly allocated digest context.

  @retval TRUE   SM3 context initialization succeeded.
  @retval FALSE  SM3 context initialization failed.

**/
BOOLEAN
EFIAPI
Sm3Init (
  OUT  VOID  **Sm3CtxPtr
  )
{

  RETURN_STATUS success;
  EVP_MD_CTX *ctx;

  if (Sm3CtxPtr == NULL) {
    return FALSE;
  }

  ctx = EVP_MD_CTX_new();

  if (ctx == NULL) {
    return FALSE;
  }

  success = EVP_DigestInit(ctx, EVP_sm3());

  if (success == 0) {
    return FALSE;
  }

  *Sm3CtxPtr = ctx;

  return TRUE;
}

/**
  Digests the input data and updates SM3 context.

  This function performs SM3 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or
  discontinuous data streams. SM3 context should be already correctly
  initialized by Sm3Init(), and should not be finalized by Sm3Final().
  Behavior with invalid context is undefined.

  If Sm3Ctx is NULL, then return FALSE.

  @param[in, out]  Sm3Ctx         Pointer to the SM3 context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval TRUE   SM3 data digest succeeded.
  @retval FALSE  SM3 data digest failed.

**/
BOOLEAN
EFIAPI
Sm3Update (
  IN OUT  VOID        *Sm3Ctx,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{

  if (Sm3Ctx == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  return (BOOLEAN) (EVP_DigestUpdate(Sm3Ctx, Data, DataSize));
}

/**
  Completes computation of the SM3 digest value.

  This function completes SM3 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SM3 context cannot
  be used again.
  SM3 context should be already correctly initialized by Sm3Init(), and should not be
  finalized by Sm3Final(). Behavior with invalid SM3 context is undefined.

  If Sm3Ctx is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @param[in, out]  Sm3Ctx         Pointer to the SM3 context.
  @param[out]      HashValue      Pointer to a buffer that receives the SM3 digest
                                  value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.

**/
BOOLEAN
EFIAPI
Sm3Final (
  IN OUT  VOID   *Sm3Ctx,
  OUT     UINT8  *HashValue
  )
{

  if (Sm3Ctx == NULL || HashValue == NULL) {
    return FALSE;
  }

  return (BOOLEAN)(EVP_DigestFinal(Sm3Ctx, HashValue, NULL /*bytesWritten*/));

  return TRUE;
}

/**
  Computes the SM3 message digest of an input data buffer.

  This function performs the SM3 message digest of a given data buffer, and places
  the digest value into the specified memory location.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SM3 digest
                           value (32 bytes).

  @retval TRUE   SM3 digest computation succeeded.
  @retval FALSE  SM3 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sm3HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  INTN success;
  EVP_MD_CTX* ctx;

  //
  // Check input parameters.
  //
  if (HashValue == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  ctx = EVP_MD_CTX_new();

  if (ctx == NULL) {
    return FALSE;
  }

  success = EVP_Digest(Data, DataSize, HashValue, NULL /*bytes written*/,
                      EVP_sm3(), NULL /*impl*/);

  if (success == 0) {
    return FALSE;
  }

  return TRUE;
}
