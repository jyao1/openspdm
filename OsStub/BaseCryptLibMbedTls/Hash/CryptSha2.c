/** @file
  SHA-2 Digest Wrapper Implementations over mbedTLS

  This file includes SHA256, SHA384, SHA512, all part of SHA-2 family.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

typedef enum {
  _SHA2_256,
  _SHA2_384,
  _SHA2_512
} INTERNAL_SHA2_TYPE;

/**

  Computes the size of a mbedtls_sha{256, 512}_context struct given a
  Sha2Type. Note that 384 and 512 both use mbedtls_sha512_context.

  @param[in]   type     Algorithm requested. Must be supported.

  @retval UINTN > 0   The size of the corresponding context struct.
  @retval UINTN == 0   Error; algorithm not supported.

**/
STATIC
UINTN
GetContextSize(
  IN INTERNAL_SHA2_TYPE type
)
{
  switch (type) {
    case _SHA2_256:
    {
      return (UINTN)(sizeof(mbedtls_sha256_context));
    }
    case _SHA2_384:
    case _SHA2_512:
    {
      return (UINTN)(sizeof(mbedtls_sha512_context));
    }
  }

  return 0;
}

/**

  Given a Sha2Type, allocate, initialize, and return a pointer to an
  initialized context struct.

  Note that this function will allocate.

  @param[in]   type     Algorithm requested. Must be supported.

  @retval VOID* != NULL An initialized context structure supporting algorithm `type`.
  @retval VOID* == NULL Error; requested context could not be initialized.

**/
STATIC
VOID*
InitAndStartShaContext(
  IN INTERNAL_SHA2_TYPE type
)
{
  VOID* ctx;

  ctx = (VOID*)AllocatePool(GetContextSize(type));

  if (ctx == NULL) {
    return FALSE;
  }

  switch (type) {
    case _SHA2_256:
    {
      mbedtls_sha256_init (ctx);
      if (mbedtls_sha256_starts_ret(ctx, FALSE /*is224*/) == 0) {
        return ctx;
      }
      break;
    }
    case _SHA2_384:
    {
      mbedtls_sha512_init (ctx);
      if (mbedtls_sha512_starts_ret(ctx, TRUE /*is384*/) == 0){
        return ctx;
      }
      break;
    }
    case _SHA2_512:
    {
      mbedtls_sha512_init (ctx);
      if (mbedtls_sha512_starts_ret(ctx, FALSE /*is384*/) == 0) {
        return ctx;
      }
      break;
    }
  }

  return NULL;
}

/**

  Write out the digest value present in `ctx` to `HashValue`. Then clean up
  the ctx and release all associated resources.

  @param[in]   type       Algorithm requested. Must be supported.
  @param[in]   ctx        A ShaContext that has been initialized.
  @param[in]   HashValue  A pointer to which the digest value shall be written.

  @retval TRUE   The digest value from `ctx` has been written to `HashValue`. `ctx` has been cleaned up.
  @retval FALSE  The digest value from `ctx` has not been written to `HashValue`. `ctx` has not been cleaned up.

**/
STATIC
BOOLEAN
FinishAndCleanCtx(
  IN    INTERNAL_SHA2_TYPE type,
  IN    VOID               *ctx,
  OUT   UINT8              *HashValue
)
{
  INT32 ret;

  switch (type) {
    case _SHA2_256:
    {
      ret = mbedtls_sha256_finish_ret(ctx, HashValue);
      if (ret < 0) {
        return FALSE;
      }
      mbedtls_sha256_free(ctx);
      break;
    }
    case _SHA2_384:
    case _SHA2_512:
    {
      ret = mbedtls_sha512_finish_ret(ctx, HashValue);
      if (ret < 0) {
        return FALSE;
      }
      mbedtls_sha512_free(ctx);
      break;
    }
    default: return FALSE;
  }

  FreePool(ctx);

  return TRUE;
}

BOOLEAN
EFIAPI
Sha2_InitGeneric (
  OUT VOID                **ShaCtxPtr,
  IN  INTERNAL_SHA2_TYPE  ShaType
)
{
  VOID* ctx;

  if (ShaCtxPtr == NULL) {
    return FALSE;
  }

  ctx = InitAndStartShaContext(ShaType);

  if (ctx == NULL) {
    return FALSE;
  }

  *ShaCtxPtr = ctx;

  return TRUE;
}

BOOLEAN
EFIAPI
Sha2_256Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha2_InitGeneric(ShaCtxPtr, _SHA2_256);
}

BOOLEAN
EFIAPI
Sha2_384Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha2_InitGeneric(ShaCtxPtr, _SHA2_384);
}

BOOLEAN
EFIAPI
Sha2_512Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha2_InitGeneric(ShaCtxPtr, _SHA2_512);
}

BOOLEAN
EFIAPI
Sha2_UpdateGeneric (
  IN OUT VOID                   *ShaCtx,
  IN     CONST VOID             *Data,
  IN     UINTN                  DataSize,
  IN     INTERNAL_SHA2_TYPE     ShaType
)
{
  if (ShaCtx == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  switch (ShaType) {
    case _SHA2_256:
    {
      if (mbedtls_sha256_update_ret(ShaCtx, Data, DataSize) == 0) {
        return TRUE;
      }
      break;
    }
    case _SHA2_384:
    case _SHA2_512:
    {
      if (mbedtls_sha512_update_ret(ShaCtx, Data, DataSize) == 0) {
        return TRUE;
      }
      break;
    }
  }

  return FALSE;
}

BOOLEAN
EFIAPI
Sha2_256Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha2_UpdateGeneric(ShaCtx, Data, DataSize, _SHA2_256);
}

BOOLEAN
EFIAPI
Sha2_384Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha2_UpdateGeneric(ShaCtx, Data, DataSize, _SHA2_384);
}

BOOLEAN
EFIAPI
Sha2_512Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha2_UpdateGeneric(ShaCtx, Data, DataSize, _SHA2_512);
}

BOOLEAN
EFIAPI
Sha2_FinalGeneric (
  IN     VOID                  *ShaCtx,
  OUT    UINT8                 *HashValue,
  IN     INTERNAL_SHA2_TYPE    ShaType
)
{
  if (ShaCtx == NULL || HashValue == NULL) {
    return FALSE;
  }

  return FinishAndCleanCtx(ShaType, ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha2_256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue, _SHA2_256);
}

BOOLEAN
EFIAPI
Sha2_384Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue, _SHA2_384);
}

BOOLEAN
EFIAPI
Sha2_512Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue, _SHA2_512);
}

/**
  Computes the SHA2 message digest of an input data buffer for a supported SHA2 algorithm.
  Presently, this function supports SHA-2{256, 384, 512}.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of data buffer in bytes.
  @param[in]   ShaType     Algorithm requested. Must be supported.
  @param[out]  HashValue   Pointer to a buffer to which the SHA2 digest value will be written.

  @retval TRUE   SHA2 digest computation succeeded.
  @retval FALSE  SHA2 digest computation failed.
  @retval FALSE  This interface is not supported.

**/

BOOLEAN
EFIAPI
Sha2_HashAll_Generic(
  IN   CONST VOID            *Data,
  IN   UINTN                 DataSize,
  IN   INTERNAL_SHA2_TYPE    ShaType,
  OUT  UINT8                 *HashValue
)
{
  // Check input parameters.
  if (HashValue == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  switch (ShaType) {
    case _SHA2_256:
    {
      if (mbedtls_sha256_ret(Data, DataSize, HashValue, FALSE /*is224*/) < 0) {
        return FALSE;
      }
      break;
    }
    case _SHA2_384:
    {
      if (mbedtls_sha512_ret(Data, DataSize, HashValue, TRUE /*is384*/) < 0) {
        return FALSE;
      }
      break;
    }
    case _SHA2_512:
    {
      if (mbedtls_sha512_ret(Data, DataSize, HashValue, FALSE /*is384*/) < 0) {
        return FALSE;
      }
      break;
    }
    default: return FALSE;
  }

  return TRUE;
}

BOOLEAN
EFIAPI
Sha2_256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha2_HashAll_Generic(Data, DataSize, _SHA2_256, HashValue);
}

BOOLEAN
EFIAPI
Sha2_384HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha2_HashAll_Generic(Data, DataSize, _SHA2_384, HashValue);
}

BOOLEAN
EFIAPI
Sha2_512HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha2_HashAll_Generic(Data, DataSize, _SHA2_512, HashValue);
}
