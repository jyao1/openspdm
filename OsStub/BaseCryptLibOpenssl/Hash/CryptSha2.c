/** @file
  SHA-2 Digest Wrapper Implementations over OpenSSL.

  This file includes SHA256, SHA384, SHA512, all part of SHA-2 family.

Copyright (c) 2009 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

typedef enum {
  _SHA2_256,
  _SHA2_384,
  _SHA2_512
} INTERNAL_SHA2_TYPE;

STATIC
CONST
EVP_MD*
GetMd(
  INTERNAL_SHA2_TYPE type
  )
{
  switch (type) {
    case _SHA2_256:
    {
      return EVP_sha256();
    }
    case _SHA2_384:
    {
      return EVP_sha384();
    }
    case _SHA2_512:
    {
      return EVP_sha512();
    }
    default: break;
  }

  return NULL;
}

/**

  Given a Sha2Type, allocate, initialize, and return a pointer to an
  initialized context struct.

  Note that this function will allocate.

  @param[in]   type     Algorithm requested. Must be supported.

  @retval VOID* != NULL An initialized context structure supporting algorithm `type`.
  @retval VOID* == NULL Error; requested context could not be initialized.

**/
BOOLEAN
EFIAPI
Sha2_InitGeneric (
  OUT VOID                **ShaCtxPtr,
  IN  INTERNAL_SHA2_TYPE  ShaType
)
{
  RETURN_STATUS success;
  EVP_MD_CTX *ctx;

  if (ShaCtxPtr == NULL) {
    return FALSE;
  }

  ctx = EVP_MD_CTX_new();

  if (ctx == NULL) {
    return FALSE;
  }

  success = EVP_DigestInit(ctx, GetMd(ShaType));

  if (success == 0) {
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
  IN OUT VOID               *ShaCtx,
  IN     CONST VOID         *Data,
  IN     UINTN              DataSize,
  IN     INTERNAL_SHA2_TYPE ShaType
)
{
  if (ShaCtx == NULL) {
    return FALSE;
  }

  if (Data == NULL && DataSize != 0) {
    return FALSE;
  }

  return (BOOLEAN) (EVP_DigestUpdate(ShaCtx, Data, DataSize));
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
  IN     VOID         *ShaCtx,
  OUT    UINT8        *HashValue
)
{
  if (ShaCtx == NULL || HashValue == NULL) {
    return FALSE;
  }

  return (BOOLEAN) (EVP_DigestFinal(ShaCtx, HashValue, NULL /*bytesWritten*/));
}

BOOLEAN
EFIAPI
Sha2_256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha2_384Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha2_512Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha2_FinalGeneric(ShaCtx, HashValue);
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
  RETURN_STATUS success;
  EVP_MD_CTX* ctx;

  // Check input parameters.
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
                      GetMd(ShaType), NULL /*impl*/);

  if (success == 0) {
    return FALSE;
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
