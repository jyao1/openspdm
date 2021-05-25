/** @file
  SHA-3 Digest Wrapper Implementations over mbedTLS.

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

BOOLEAN
EFIAPI
Sha3_256Init (
  OUT VOID **ShaCtxPtr
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_384Init (
  OUT VOID **ShaCtxPtr
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_512Init
(
  OUT VOID **ShaCtxPtr
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_Shake256Init (
  OUT VOID **ShaCtxPtr
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_256Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_384Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_512Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_Shake256Update (
  IN OUT VOID         *ShaCtx,
  IN     CONST VOID   *Data,
  IN     UINTN        DataSize
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_384Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_512Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_Shake256Final (
  IN  VOID  *ShaCtx,
  OUT UINT8 *HashValue
)
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_384HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_512HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return FALSE;
}

BOOLEAN
EFIAPI
Sha3_Shake256HashAll (
  IN   CONST VOID  *Data,
  IN   UINTN       DataSize,
  OUT  UINT8       *HashValue
  )
{
  return FALSE;
}
