/** @file
  SHA3-224/256/384/512 and Shake-128/256 Digest Wrapper
  Implementation over OpenSSL.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "InternalCryptLib.h"
#include <crypto/evp.h>
#include <openssl/evp.h>
#include <crypto/evp/evp_local.h>

///
/// HashAll need a buffer to store hash context
/// This size is enough to hold all sha3 hash context
///
#define INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE 1024

/**
  Retrieves the size, in bytes, of the context buffer required for S##type####bitlen## hash operations.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @return  The size, in bytes, of the context buffer required for S##type####bitlen## hash operations.

**/
#define SHA3_GET_CONETXTSIZE_IMPL(type,bitlen) \
UINTN \
EFIAPI \
S##type####bitlen##GetContextSize ( \
  VOID \
  ) \
{ \
  CONST EVP_MD      *EvpMd; \
  struct evp_md_st  *EvpMdSt; \
\
  EvpMd = EVP_s##type####bitlen (); \
  EvpMdSt = (struct evp_md_st  *)EvpMd; \
\
  return (UINTN)(EvpMdSt->ctx_size + sizeof (struct evp_md_ctx_st)); \
}

/**
  Initializes user-supplied memory pointed by S##type####bitlen##Context as S##type####bitlen## hash context for
  subsequent use.

  If S##type####bitlen##Context is NULL, then return FALSE.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @param[out]  S##type####bitlen##Context  Pointer to S##type####bitlen##Context context being initialized.

  @retval TRUE   S##type####bitlen##Context context initialization succeeded.
  @retval FALSE  S##type####bitlen##Context context initialization failed.

**/
#define SHA3_INIT_IMPL(type,bitlen) \
BOOLEAN \
EFIAPI \
S##type####bitlen##Init ( \
  OUT  VOID  *S##type####bitlen##Context \
  ) \
{\
  CONST     EVP_MD      *EvpMd; \
  struct evp_md_st      *EvpMdSt; \
  struct evp_md_ctx_st  *EvpMdCtx; \
\
  EvpMd = EVP_s##type####bitlen (); \
\
  EvpMdCtx = (struct evp_md_ctx_st *)S##type####bitlen##Context; \
  EvpMdCtx->md_data = (UINT8*)S##type####bitlen##Context + sizeof (struct evp_md_ctx_st); \
  EvpMdCtx->digest = EvpMd; \
  EvpMdCtx->engine = NULL; \
  EvpMdSt = (struct evp_md_st  *)EvpMd; \
\
  return (BOOLEAN) EvpMdSt->init(EvpMdCtx); \
}

/**
  Makes a copy of an existing S##type####bitlen##Context context.

  If S##type####bitlen##Context is NULL, then return FALSE.
  If NewS##type####bitlen##Context is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @param[in]  S##type####bitlen##Context     Pointer to S##type####bitlen## context being copied.
  @param[out] NewS##type####bitlen##Context  Pointer to new S##type####bitlen## context.

  @retval TRUE   S##type####bitlen## context copy succeeded.
  @retval FALSE  S##type####bitlen## context copy failed.
  @retval FALSE  This interface is not supported.

**/
#define SHA3_DUPLICATE_IMPL(type,bitlen) \
BOOLEAN \
EFIAPI \
S##type####bitlen##Duplicate ( \
  IN   CONST VOID  *S##type####bitlen##Context, \
  OUT  VOID        *NewS##type####bitlen##Context \
  ) \
{ \
  UINTN CtxSize; \
  if (S##type####bitlen##Context == NULL || NewS##type####bitlen##Context == NULL) { \
    return FALSE; \
  } \
\
  CtxSize = S##type####bitlen##GetContextSize(); \
  CopyMem (NewS##type####bitlen##Context, S##type####bitlen##Context, CtxSize); \
  return TRUE; \
}

/**
  Digests the input data and updates S##type####bitlen## context.

  This function performs S##type####bitlen## digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  S##type####bitlen## context should be already correctly initialized by S##type####bitlen##Init(), and should not be finalized
  by S##type####bitlen##Final(). Behavior with invalid context is undefined.

  If S##type####bitlen##Context is NULL, then return FALSE.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @param[in, out]  S##type####bitlen##Context  Pointer to the S##type####bitlen## context.
  @param[in]       Data           Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize       Size of Data buffer in bytes.

  @retval TRUE   S##type####bitlen## data digest succeeded.
  @retval FALSE  S##type####bitlen## data digest failed.

**/
#define SHA3_UPDATE_IMPL(type,bitlen) \
BOOLEAN \
EFIAPI \
S##type####bitlen##Update ( \
  IN OUT  VOID        *S##type####bitlen##Context, \
  IN      CONST VOID  *Data, \
  IN      UINTN       DataSize \
  ) \
{ \
  CONST     EVP_MD      *EvpMd; \
  struct evp_md_st      *EvpMdSt; \
  struct evp_md_ctx_st  *EvpMdCtx; \
\
  EvpMdCtx = (struct evp_md_ctx_st *)S##type####bitlen##Context; \
\
  EvpMd = EVP_s##type####bitlen (); \
  EvpMdSt = (struct evp_md_st *)EvpMd; \
\
  return (BOOLEAN) EvpMdSt->update(EvpMdCtx, Data, (size_t)DataSize); \
}

/**
  Completes computation of the S##type####bitlen## digest value.

  This function completes S##type####bitlen## hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the S##type####bitlen## context cannot
  be used again.
  S##type####bitlen## context should be already correctly initialized by S##type####bitlen##Init(), and should not be
  finalized by S##type####bitlen##Final(). Behavior with invalid S##type####bitlen## context is undefined.

  If S##type####bitlen##Context is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @param[in, out]  S##type####bitlen##Context  Pointer to the S##type####bitlen## context.
  @param[out]      HashValue      Pointer to a buffer that receives the S##type####bitlen## digest
                                  value (bitlen / 8 bytes).

  @retval TRUE   S##type####bitlen## digest computation succeeded.
  @retval FALSE  S##type####bitlen## digest computation failed.

**/
#define SHA3_FINAL_IMPL(type,bitlen) \
BOOLEAN \
EFIAPI \
S##type####bitlen##Final ( \
  IN OUT  VOID   *S##type####bitlen##Context, \
  OUT     UINT8  *HashValue \
  ) \
{ \
  CONST     EVP_MD      *EvpMd; \
  struct evp_md_st      *EvpMdSt; \
  struct evp_md_ctx_st  *EvpMdCtx; \
\
  EvpMdCtx = (struct evp_md_ctx_st *)S##type####bitlen##Context; \
\
  EvpMd = EVP_s##type####bitlen (); \
  EvpMdSt = (struct evp_md_st *)EvpMd; \
\
  return (BOOLEAN) EvpMdSt->final(EvpMdCtx, HashValue); \
}

/**
  Computes the S##type####bitlen## message digest of a input data buffer.

  This function performs the S##type####bitlen## message digest of a given data buffer, and places
  the digest value into the specified memory.

  If this interface is not supported, then return FALSE.

  @type    "ha3_" is stand for Sha3##bitlen##, "hake" is stand for Shake##bitlen##
  @bitlen  Hash len, for "ha3_" avaiable value is 224,256,384,512 for "hake" abaiable value is 128,256

  @param[in]   Data        Pointer to the buffer containing the data to be hashed.
  @param[in]   DataSize    Size of Data buffer in bytes.
  @param[out]  HashValue   Pointer to a buffer that receives the S##type####bitlen## digest
                           value (bitlen / 8 bytes).

  @retval TRUE   S##type####bitlen## digest computation succeeded.
  @retval FALSE  S##type####bitlen## digest computation failed.
  @retval FALSE  This interface is not supported.

**/
#define SHA3_HASHAll_IMPL(type,bitlen) \
BOOLEAN \
EFIAPI \
S##type####bitlen##HashAll ( \
  IN   CONST VOID  *Data, \
  IN   UINTN       DataSize, \
  OUT  UINT8       *HashValue \
  ) \
{ \
  BOOLEAN   Status; \
  UINT8     HashContext[INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE]; \
\
  ZeroMem (HashContext, INTERNAL_MAX_CONTEXT_SIZE_FOR_HASHALL_USE); \
  Status = S##type####bitlen##Init (HashContext); \
  if (Status) { \
    Status = S##type####bitlen##Update (HashContext, Data, DataSize); \
  } \
  if (Status) { \
    Status = S##type####bitlen##Final (HashContext, HashValue); \
  } \
\
  return Status; \
}

#define SHA3_IMPL(bitlen) \
SHA3_GET_CONETXTSIZE_IMPL(ha3_, bitlen) \
SHA3_INIT_IMPL(ha3_, bitlen) \
SHA3_DUPLICATE_IMPL(ha3_, bitlen) \
SHA3_UPDATE_IMPL(ha3_, bitlen) \
SHA3_FINAL_IMPL(ha3_, bitlen) \
SHA3_HASHAll_IMPL(ha3_, bitlen)

#define SHAKE_IMP(bitlen) \
SHA3_GET_CONETXTSIZE_IMPL(hake, bitlen) \
SHA3_INIT_IMPL(hake, bitlen) \
SHA3_DUPLICATE_IMPL(hake, bitlen) \
SHA3_UPDATE_IMPL(hake, bitlen) \
SHA3_FINAL_IMPL(hake, bitlen) \
SHA3_HASHAll_IMPL(hake, bitlen)

SHA3_IMPL(224)
SHA3_IMPL(256)
SHA3_IMPL(384)
SHA3_IMPL(512)

SHAKE_IMP(128)
SHAKE_IMP(256)
