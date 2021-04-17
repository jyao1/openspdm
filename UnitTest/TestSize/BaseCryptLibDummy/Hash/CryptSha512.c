/** @file
  SHA-384 and SHA-512 Digest Wrapper Implementations over OpenSSL.

Copyright (c) 2014 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

/**
  Allocates a new digest context, and returns a reference through the outparam `ShaCtxPtr`.

  If ShaCtxPtr is NULL, then return FALSE.

  @param[out]  ShaCtxPtr  Pointer to the pointer of the newly allocated digest context.

  @retval TRUE   SHA-384 context initialization succeeded.
  @retval FALSE  SHA-384 context initialization failed.

**/
BOOLEAN
EFIAPI
Sha2_384Init (
  OUT  VOID  **ShaCtxPtr
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Digests the input data and updates SHA-384 context.

  This function performs SHA-384 digest on a data buffer of the specified
  size. It can be called multiple times to compute the digest of long or
  discontinuous data streams. SHA-384 context should be already correctly
  initialized by Sha2_384Init(), and should not be finalized by
  Sha2_384Final(). Behavior with invalid context is undefined.

  If ShaCtx is NULL, then return FALSE.

  @param[in, out]  ShaCtx         Pointer to the SHA-384 context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval TRUE   SHA-384 data digest succeeded.
  @retval FALSE  SHA-384 data digest failed.

**/
BOOLEAN
EFIAPI
Sha2_384Update (
  IN OUT  VOID        *ShaCtx,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Completes computation of the SHA-384 digest value.

  This function completes SHA-384 hash computation and retrieves the digest
  value into the specified memory. After this function has been called, the
  SHA-384 context cannot be used again. SHA-384 context should be already
  correctly initialized by Sha2_384Init(), and should not be finalized by
  Sha2_384Final(). Behavior with invalid SHA-384 context is undefined.

  If ShaCtx is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @param[in, out]  ShaCtx         Pointer to the SHA-384 context.
  @param[out]      HashValue      Pointer to a buffer that receives the SHA-384 digest
                                  value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.

**/
BOOLEAN
EFIAPI
Sha2_384Final (
  IN OUT  VOID   *ShaCtx,
  OUT     UINT8  *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Computes the SHA-384 message digest of a input data buffer.

  This function performs the SHA-384 message digest of a given data buffer,
  and places the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SHA-384 digest
                           value (48 bytes).

  @retval TRUE   SHA-384 digest computation succeeded.
  @retval FALSE  SHA-384 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sha2_384HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}


/**
  Allocates a new digest context, and returns a reference through the outparam `ShaCtxPtr`.

  If ShaCtxPtr is NULL, then return FALSE.

  @param[out]  ShaCtxPtr  Pointer to the pointer of the newly allocated digest context.

  @retval TRUE   SHA-512 context initialization succeeded.
  @retval FALSE  SHA-512 context initialization failed.

**/
BOOLEAN
EFIAPI
Sha2_512Init (
  OUT  VOID  **ShaCtxPtr
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Digests the input data and updates SHA-512 context.

  This function performs SHA-512 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  SHA-512 context should be already correctly initialized by Sha2_512Init(), and should not be finalized
  by Sha2_512Final(). Behavior with invalid context is undefined.

  If ShaCtx is NULL, then return FALSE.

  @param[in, out]  ShaCtx         Pointer to the SHA-512 context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval TRUE   SHA-512 data digest succeeded.
  @retval FALSE  SHA-512 data digest failed.

**/
BOOLEAN
EFIAPI
Sha2_512Update (
  IN OUT  VOID        *ShaCtx,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Completes computation of the SHA-512 digest value.

  This function completes SHA-512 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the SHA-512 context cannot
  be used again.
  SHA-512 context should be already correctly initialized by Sha2_512Init(), and should not be
  finalized by Sha2_512Final(). Behavior with invalid SHA-512 context is undefined.

  If ShaCtx is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @param[in, out]  ShaCtx  Pointer to the SHA-512 context.
  @param[out]      HashValue      Pointer to a buffer that receives the SHA-512 digest
                                  value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.

**/
BOOLEAN
EFIAPI
Sha2_512Final (
  IN OUT  VOID   *ShaCtx,
  OUT     UINT8  *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}

/**
  Computes the SHA-512 message digest of a input data buffer.

  This function performs the SHA-512 message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the SHA-512 digest
                           value (64 bytes).

  @retval TRUE   SHA-512 digest computation succeeded.
  @retval FALSE  SHA-512 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sha2_512HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  ASSERT(FALSE);
  return FALSE;
}
