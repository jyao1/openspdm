/** @file
  SHA-256 Digest Wrapper Implementation over OpenSSL.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates a new digest context, and returns a reference through the outparam `ShaCtxPtr`.

  If ShaCtxPtr is NULL, then return FALSE.

  @param[out]  ShaCtxPtr  Pointer to the pointer of the newly allocated digest context.

  @retval TRUE   SHA-256 context initialization succeeded.
  @retval FALSE  SHA-256 context initialization failed.

**/
BOOLEAN
EFIAPI
Sha2_256Init (
  OUT  VOID  **ShaCtxPtr
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Digests the input data and updates SHA-256 context.

  This function performs SHA-256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-256 context should be already correctly initialized by Sha2_256Init(), and should not be finalized
  by Sha2_256Final(). Behavior with invalid context is undefined.

  If ShaCtx is NULL, then return FALSE.

  @param[in, out]  ShaCtx         Pointer to the SHA-256 context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval TRUE   SHA-256 data digest succeeded.
  @retval FALSE  SHA-256 data digest failed.

**/
BOOLEAN
EFIAPI
Sha2_256Update (
  IN OUT  VOID        *ShaCtx,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Completes computation of the SHA-256 digest value.

  This function completes SHA-256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-256 context cannot
  be used again.
  SHA-256 context should be already correctly initialized by Sha2_256Init(), and should not be
  finalized by Sha2_256Final(). Behavior with invalid SHA-256 context is undefined.

  If ShaCtx is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @param[in, out]  ShaCtx  Pointer to the SHA-256 context.
  @param[out]      HashValue      Pointer to a buffer that receives the SHA-256 digest
                                  value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.

**/
BOOLEAN
EFIAPI
Sha2_256Final (
  IN OUT  VOID   *ShaCtx,
  OUT     UINT8  *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Computes the SHA-256 message digest of a input data buffer.

  This function performs the SHA-256 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SHA-256 digest
                           value (32 bytes).

  @retval TRUE   SHA-256 digest computation succeeded.
  @retval FALSE  SHA-256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sha2_256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}
