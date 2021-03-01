/** @file
  Application for Hash Primitives Validation.

Copyright (c) 2010 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

//
// Max Known Digest Size is SHA512 Output (64 bytes) by far
//
#define MAX_DIGEST_SIZE    64

//
// Message string for digest validation
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST CHAR8 *HashData = "abc";

//
// Result for SHA-256("abc"). (From "B.1 SHA-256 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha256Digest[SHA256_DIGEST_SIZE] = {
  0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
  0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
  };

//
// Result for SHA-384("abc"). (From "D.1 SHA-384 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha384Digest[SHA384_DIGEST_SIZE] = {
  0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
  0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
  0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
  };

//
// Result for SHA-512("abc"). (From "C.1 SHA-512 Example" of NIST FIPS 180-2)
//
GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha512Digest[SHA512_DIGEST_SIZE] = {
  0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
  0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
  0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
  0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
  };

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha3_256Digest[SHA3_256_DIGEST_SIZE] = {
  0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
  0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha3_384Digest[SHA3_384_DIGEST_SIZE] = {
  0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
  0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
  0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sha3_512Digest[SHA3_512_DIGEST_SIZE] = {
  0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
  0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
  0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
  0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Shake256Digest[SHAKE256_DIGEST_SIZE] = {
  0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
  0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 Sm3_256Digest[SHAKE256_DIGEST_SIZE] = {
  0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
  0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

/**
  Validate UEFI-OpenSSL Digest Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptDigest (
  VOID
  )
{
  UINTN    CtxSize;
  VOID     *HashCtx;
  UINTN    DataSize;
  UINT8    Digest[MAX_DIGEST_SIZE];
  BOOLEAN  Status;

  Print (" UEFI-OpenSSL Hash Engine Testing:\n");
  DataSize = AsciiStrLen (HashData);

  Print ("- SHA256: ");

  //
  // SHA256 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha256GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Init... ");
  Status  = Sha256Init (HashCtx);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Update... ");
  Status  = Sha256Update (HashCtx, HashData, DataSize);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Finalize... ");
  Status  = Sha256Final (HashCtx, Digest);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  FreePool (HashCtx);

  Print ("Check Value... ");
  if (CompareMem (Digest, Sha256Digest, SHA256_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("HashAll... ");
  ZeroMem (Digest, SHA256_DIGEST_SIZE);
  Status  = Sha256HashAll (HashData, DataSize, Digest);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem (Digest, Sha256Digest, SHA256_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");

  Print ("- SHA384: ");

  //
  // SHA384 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha384GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Init... ");
  Status  = Sha384Init (HashCtx);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Update... ");
  Status  = Sha384Update (HashCtx, HashData, DataSize);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Finalize... ");
  Status  = Sha384Final (HashCtx, Digest);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  FreePool (HashCtx);

  Print ("Check Value... ");
  if (CompareMem (Digest, Sha384Digest, SHA384_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("HashAll... ");
  ZeroMem (Digest, SHA384_DIGEST_SIZE);
  Status  = Sha384HashAll (HashData, DataSize, Digest);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem (Digest, Sha384Digest, SHA384_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");

  Print ("- SHA512: ");

  //
  // SHA512 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha512GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx == NULL) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("Init... ");
  Status  = Sha512Init (HashCtx);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Update... ");
  Status  = Sha512Update (HashCtx, HashData, DataSize);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  Print ("Finalize... ");
  Status  = Sha512Final (HashCtx, Digest);
  if (!Status) {
    Print ("[Fail]");
    FreePool (HashCtx);
    return EFI_ABORTED;
  }

  FreePool (HashCtx);

  Print ("Check Value... ");
  if (CompareMem (Digest, Sha512Digest, SHA512_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("HashAll... ");
  ZeroMem (Digest, SHA512_DIGEST_SIZE);
  Status  = Sha512HashAll (HashData, DataSize, Digest);
  if (!Status) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem (Digest, Sha512Digest, SHA512_DIGEST_SIZE) != 0) {
    Print ("[Fail]");
    return EFI_ABORTED;
  }

  Print ("[Pass]\n");

  Print ("- SHA3_256: ");
  //
  // SHA3_256 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha3_256GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx != NULL) {
    Print ("Init... ");
    Status  = Sha3_256Init (HashCtx);
  }

  if (Status) {
    Print ("Update... ");
    Status  = Sha3_256Update (HashCtx, HashData, DataSize);
  }

  if (Status) {
    Print ("Finalize... ");
    Status  = Sha3_256Final (HashCtx, Digest);
  }

  if (Status) {
    Print ("Check Value... ");
    if (CompareMem (Digest, Sha3_256Digest, SHA3_256_DIGEST_SIZE) == 0) {
      Status = TRUE;
    } else {
      Status = FALSE;
    }
  }

  if (HashCtx != NULL) {
    FreePool(HashCtx);
  }

  if (Status) {
    Print ("HashAll... ");
    ZeroMem (Digest, SHA3_256_DIGEST_SIZE);
    Status  = Sha3_256HashAll (HashData, DataSize, Digest);
  }
  if (Status) {
    Print ("[Pass]\n");
  } else {
    Print ("[Failed]\n");
  }

  Print ("- SHA3_384: ");
  //
  // SHA3_384 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha3_384GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx != NULL) {
    Print ("Init... ");
    Status  = Sha3_384Init (HashCtx);
  }

  if (Status) {
    Print ("Update... ");
    Status  = Sha3_384Update (HashCtx, HashData, DataSize);
  }

  if (Status) {
    Print ("Finalize... ");
    Status  = Sha3_384Final (HashCtx, Digest);
  }

  if (Status) {
    Print ("Check Value... ");
    if (CompareMem (Digest, Sha3_384Digest, SHA3_384_DIGEST_SIZE) == 0) {
      Status = TRUE;
    } else {
      Status = FALSE;
    }
  }

  if (HashCtx != NULL) {
    FreePool(HashCtx);
  }

  if (Status) {
    Print ("HashAll... ");
    ZeroMem (Digest, SHA3_384_DIGEST_SIZE);
    Status  = Sha3_384HashAll (HashData, DataSize, Digest);
  }
  if (Status) {
    Print ("[Pass]\n");
  } else {
    Print ("[Failed]\n");
  }

  Print ("- SHA3_512: ");
  //
  // SHA3_512 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Sha3_512GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx != NULL) {
    Print ("Init... ");
    Status  = Sha3_512Init (HashCtx);
  }

  if (Status) {
    Print ("Update... ");
    Status  = Sha3_512Update (HashCtx, HashData, DataSize);
  }

  if (Status) {
    Print ("Finalize... ");
    Status  = Sha3_512Final (HashCtx, Digest);
  }

  if (Status) {
    Print ("Check Value... ");
    if (CompareMem (Digest, Sha3_512Digest, SHA3_512_DIGEST_SIZE) == 0) {
      Status = TRUE;
    } else {
      Status = FALSE;
    }
  }

  if (HashCtx != NULL) {
    FreePool(HashCtx);
  }

  if (Status) {
    Print ("HashAll... ");
    ZeroMem (Digest, SHA3_512_DIGEST_SIZE);
    Status  = Sha3_512HashAll (HashData, DataSize, Digest);
  }
  if (Status) {
    Print ("[Pass]\n");
  } else {
    Print ("[Failed]\n");
  }

  Print ("- SHAKE256: ");
  //
  // SHAKE256 Digest Validation
  //
  ZeroMem (Digest, MAX_DIGEST_SIZE);
  CtxSize = Shake256GetContextSize ();
  HashCtx = AllocatePool (CtxSize);
  if (HashCtx != NULL) {
    Print ("Init... ");
    Status  = Shake256Init (HashCtx);
  }

  if (Status) {
    Print ("Update... ");
    Status  = Shake256Update (HashCtx, HashData, DataSize);
  }

  if (Status) {
    Print ("Finalize... ");
    Status  = Shake256Final (HashCtx, Digest);
  }

  if (Status) {
    Print ("Check Value... ");
    if (CompareMem (Digest, Shake256Digest, SHAKE256_DIGEST_SIZE) == 0) {
      Status = TRUE;
    } else {
      Status = FALSE;
    }
  }

  if (HashCtx != NULL) {
    FreePool(HashCtx);
  }

  if (Status) {
    Print ("HashAll... ");
    ZeroMem (Digest, SHAKE256_DIGEST_SIZE);
    Status  = Shake256HashAll (HashData, DataSize, Digest);
  }
  if (Status) {
    Print ("[Pass]\n");
  } else {
    Print ("[Failed]\n");
  }

  Print ("- SM3_256: ");
  //
  // SM3_256 Digest Validation
  //
  Print ("HashAll... ");
  ZeroMem (Digest, SM3_256_DIGEST_SIZE);
  Status  = Sm3HashAll (HashData, DataSize, Digest);
  if (Status) {
    if (CompareMem (Digest, Sm3_256Digest, SM3_256_DIGEST_SIZE) == 0) {
      Status = TRUE;
    } else {
      Status = FALSE;
    }
  }
  if (Status) {
    Print ("[Pass]\n");
  } else {
    Print ("[Failed]\n");
  }

  return EFI_SUCCESS;
}
