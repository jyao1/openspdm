/** @file
  HMAC-SHA256 Wrapper Implementation over OpenSSL.

Copyright (c) 2016 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/md.h>

/**
  Allocates and initializes one HMAC_CTX context for subsequent HMAC-SHA256 use.

  @return  Pointer to the HMAC_CTX context that has been initialized.
           If the allocations fails, HmacSha256New() returns NULL.

**/
VOID *
EFIAPI
HmacSha256New (
  VOID
  )
{
  VOID  *HmacSha256Ctx;

  HmacSha256Ctx = AllocateZeroPool (sizeof(mbedtls_md_context_t));
  if (HmacSha256Ctx == NULL) {
    return NULL;
  }

  return HmacSha256Ctx;
}

/**
  Release the specified HMAC_CTX context.

  @param[in]  HmacSha256Ctx  Pointer to the HMAC_CTX context to be released.

**/
VOID
EFIAPI
HmacSha256Free (
  IN  VOID  *HmacSha256Ctx
  )
{
  mbedtls_md_free (HmacSha256Ctx);
}

/**
  Set user-supplied key for subsequent use. It must be done before any
  calling to HmacSha256Update().

  If HmacSha256Context is NULL, then return FALSE.

  @param[out]  HmacSha256Context  Pointer to HMAC-SHA256 context.
  @param[in]   Key                Pointer to the user-supplied key.
  @param[in]   KeySize            Key size in bytes.

  @retval TRUE   The Key is set successfully.
  @retval FALSE  The Key is set unsuccessfully.

**/
BOOLEAN
EFIAPI
HmacSha256SetKey (
  OUT  VOID         *HmacSha256Context,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize
  )
{
  const mbedtls_md_info_t *md_info;
  INT32                   Ret;

  if (HmacSha256Context == NULL || KeySize > INT_MAX) {
    return FALSE;
  }

  ZeroMem (HmacSha256Context, sizeof(mbedtls_md_context_t));
  mbedtls_md_init (HmacSha256Context);

  md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
  ASSERT(md_info != NULL);

  Ret = mbedtls_md_setup (HmacSha256Context, md_info, 1);
  if (Ret != 0) {
    return FALSE;
  }

  Ret = mbedtls_md_hmac_starts (HmacSha256Context, Key, KeySize);
  if (Ret != 0) {
    return FALSE;
  }
  return TRUE;
}

/**
  Makes a copy of an existing HMAC-SHA256 context.

  If HmacSha256Context is NULL, then return FALSE.
  If NewHmacSha256Context is NULL, then return FALSE.

  @param[in]  HmacSha256Context     Pointer to HMAC-SHA256 context being copied.
  @param[out] NewHmacSha256Context  Pointer to new HMAC-SHA256 context.

  @retval TRUE   HMAC-SHA256 context copy succeeded.
  @retval FALSE  HMAC-SHA256 context copy failed.

**/
BOOLEAN
EFIAPI
HmacSha256Duplicate (
  IN   CONST VOID  *HmacSha256Context,
  OUT  VOID        *NewHmacSha256Context
  )
{
  INT32                   Ret;

  if (HmacSha256Context == NULL || NewHmacSha256Context == NULL) {
    return FALSE;
  }

  Ret = mbedtls_md_clone (NewHmacSha256Context, HmacSha256Context);
  if (Ret != 0) {
    return FALSE;
  }
  return TRUE;
}

/**
  Digests the input data and updates HMAC-SHA256 context.

  This function performs HMAC-SHA256 digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  HMAC-SHA256 context should be initialized by HmacSha256New(), and should not be finalized
  by HmacSha256Final(). Behavior with invalid context is undefined.

  If HmacSha256Context is NULL, then return FALSE.

  @param[in, out]  HmacSha256Context Pointer to the HMAC-SHA256 context.
  @param[in]       Data              Pointer to the buffer containing the data to be digested.
  @param[in]       DataSize          Size of Data buffer in bytes.

  @retval TRUE   HMAC-SHA256 data digest succeeded.
  @retval FALSE  HMAC-SHA256 data digest failed.

**/
BOOLEAN
EFIAPI
HmacSha256Update (
  IN OUT  VOID        *HmacSha256Context,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  )
{
  INT32                   Ret;

  if (HmacSha256Context == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }
  if (DataSize > INT_MAX) {
    return FALSE;
  }

  Ret = mbedtls_md_hmac_update (HmacSha256Context, Data, DataSize);
  if (Ret != 0) {
    return FALSE;
  }
  return TRUE;
}

/**
  Completes computation of the HMAC-SHA256 digest value.

  This function completes HMAC-SHA256 hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the HMAC-SHA256 context cannot
  be used again.
  HMAC-SHA256 context should be initialized by HmacSha256New(), and should not be finalized
  by HmacSha256Final(). Behavior with invalid HMAC-SHA256 context is undefined.

  If HmacSha256Context is NULL, then return FALSE.
  If HmacValue is NULL, then return FALSE.

  @param[in, out]  HmacSha256Context  Pointer to the HMAC-SHA256 context.
  @param[out]      HmacValue          Pointer to a buffer that receives the HMAC-SHA256 digest
                                      value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.

**/
BOOLEAN
EFIAPI
HmacSha256Final (
  IN OUT  VOID   *HmacSha256Context,
  OUT     UINT8  *HmacValue
  )
{
  INT32                   Ret;

  if (HmacSha256Context == NULL || HmacValue == NULL) {
    return FALSE;
  }

  Ret = mbedtls_md_hmac_finish (HmacSha256Context, HmacValue);
  mbedtls_md_free(HmacSha256Context);
  if (Ret != 0) {
    return FALSE;
  }
  return TRUE;
}

/**
  Computes the HMAC-SHA256 digest of a input data buffer.

  This function performs the HMAC-SHA256 digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.
  
  @param[in]   Data        Pointer to the buffer containing the data to be digested.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[in]   Key         Pointer to the user-supplied key.
  @param[in]   KeySize     Key size in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the HMAC-SHA256 digest
                           value (32 bytes).

  @retval TRUE   HMAC-SHA256 digest computation succeeded.
  @retval FALSE  HMAC-SHA256 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
HmacSha256All (
  IN   CONST VOID   *Data,
  IN   UINTN        DataSize,
  IN   CONST UINT8  *Key,
  IN   UINTN        KeySize,
  OUT  UINT8       *HmacValue
  )
{
  const mbedtls_md_info_t *md_info;
  INT32                   Ret;

  md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
  ASSERT(md_info != NULL);

  Ret = mbedtls_md_hmac (md_info, Key, KeySize, Data, DataSize, HmacValue);
  if (Ret != 0) {
    return FALSE;
  }
  return TRUE;
}