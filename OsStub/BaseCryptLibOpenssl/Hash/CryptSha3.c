/** @file
  SHA-3 Digest Wrapper Implementations over OpenSSL.

  This file includes SHA3-256, SHA3-384, SHA-512, SHAKE-256, all part of
  SHA-3 family.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"

typedef enum {
_SHA3_256,
_SHA3_384,
_SHA3_512,
_SHAKE_256
} INTERNAL_SHA3_TYPE;


STATIC
CONST
EVP_MD*
GetMd(
  INTERNAL_SHA3_TYPE type
  )
{
  switch (type) {
    case _SHA3_256:
    {
      return EVP_sha3_256();
    }
    case _SHA3_384:
    {
      return EVP_sha3_384();
    }
    case _SHA3_512:
    {
      return EVP_sha3_512();
    }
    case _SHAKE_256:
    {
      return EVP_shake256();
    }
    default: break;
  }

  return NULL;
}

/**

  Given a Sha3Type, allocate, initialize, and return a pointer to an
  initialized context struct.

  Note that this function will allocate.

  @param[in]   type     Algorithm requested. Must be supported.

  @retval VOID* != NULL An initialized context structure supporting algorithm `type`.
  @retval VOID* == NULL Error; requested context could not be initialized.

**/
BOOLEAN
EFIAPI
Sha3_InitGeneric (
  OUT VOID               **ShaCtxPtr,
  IN  INTERNAL_SHA3_TYPE ShaType
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
Sha3_256Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha3_InitGeneric(ShaCtxPtr, _SHA3_256);
}

BOOLEAN
EFIAPI
Sha3_384Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha3_InitGeneric(ShaCtxPtr, _SHA3_384);
}

BOOLEAN
EFIAPI
Sha3_512Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha3_InitGeneric(ShaCtxPtr, _SHA3_512);
}

BOOLEAN
EFIAPI
Sha3_Shake256Init (
  OUT VOID **ShaCtxPtr
)
{
  return Sha3_InitGeneric(ShaCtxPtr, _SHAKE_256);
}

BOOLEAN
EFIAPI
Sha3_UpdateGeneric (
  IN OUT VOID               *ShaCtx,
  IN     CONST VOID         *Data,
  IN     UINTN              DataSize,
  IN     INTERNAL_SHA3_TYPE ShaType
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
Sha3_256Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha3_UpdateGeneric(ShaCtx, Data, DataSize, _SHA3_256);
}

BOOLEAN
EFIAPI
Sha3_384Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha3_UpdateGeneric(ShaCtx, Data, DataSize, _SHA3_384);
}

BOOLEAN
EFIAPI
Sha3_512Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha3_UpdateGeneric(ShaCtx, Data, DataSize, _SHA3_512);
}

BOOLEAN
EFIAPI
Sha3_Shake256Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return Sha3_UpdateGeneric(ShaCtx, Data, DataSize, _SHAKE_256);
}

BOOLEAN
EFIAPI
Sha3_FinalGeneric (
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
Sha3_256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha3_FinalGeneric(ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha3_384Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha3_FinalGeneric(ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha3_512Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha3_FinalGeneric(ShaCtx, HashValue);
}

BOOLEAN
EFIAPI
Sha3_Shake256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return Sha3_FinalGeneric(ShaCtx, HashValue);
}
/**
  Computes the SHA3 message digest of an input data buffer for a supported SHA3 algorithm.
  Presently, this function supports {256, 384, 512, SHAKE256}.

  If this interface is not supported, then return FALSE.

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of data buffer in bytes.
  @param[in]   ShaType     Algorithm requested. Must be supported.
  @param[out]  HashValue   Pointer to a buffer to which the SHA3-256 digest value will be written.


  @retval TRUE   SHA3 digest computation succeeded.
  @retval FALSE  SHA3 digest computation failed.
  @retval FALSE  This interface is not supported.

**/
BOOLEAN
EFIAPI
Sha3_HashAll_Generic(
  IN   CONST VOID            *Data,
  IN   UINTN                 DataSize,
  IN   INTERNAL_SHA3_TYPE    ShaType,
  OUT  UINT8                 *HashValue
)
{
  INTN success;
  EVP_MD_CTX* ctx;

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
                      GetMd(ShaType), NULL /*impl*/);


  if (success == 0) {
    return FALSE;
  }

  return TRUE;
}

BOOLEAN
EFIAPI
Sha3_256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha3_HashAll_Generic(Data, DataSize, _SHA3_256, HashValue);
}

BOOLEAN
EFIAPI
Sha3_384HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha3_HashAll_Generic(Data, DataSize, _SHA3_384, HashValue);
}

BOOLEAN
EFIAPI
Sha3_512HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha3_HashAll_Generic(Data, DataSize, _SHA3_512, HashValue);
}

BOOLEAN
EFIAPI
Sha3_Shake256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return Sha3_HashAll_Generic(Data, DataSize, _SHAKE_256, HashValue);
}
