/** @file  
  Application for Authenticated Encryption with Associated Data
  (AEAD) Validation.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Cryptest.h"

VOID
InternalDumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  );

/* AES-CCM test data from NIST public test vectors */

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_key[] = {
    0xce, 0xb0, 0x09, 0xae, 0xa4, 0x45, 0x44, 0x51, 0xfe, 0xad, 0xf0, 0xe6,
    0xb3, 0x6f, 0x45, 0x55, 0x5d, 0xd0, 0x47, 0x23, 0xba, 0xa4, 0x48, 0xe8
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_nonce[] = {
    0x76, 0x40, 0x43, 0xc4, 0x94, 0x60, 0xb7
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_adata[] = {
    0x6e, 0x80, 0xdd, 0x7f, 0x1b, 0xad, 0xf3, 0xa1, 0xc9, 0xab, 0x25, 0xc7,
    0x5f, 0x10, 0xbd, 0xe7, 0x8c, 0x23, 0xfa, 0x0e, 0xb8, 0xf9, 0xaa, 0xa5,
    0x3a, 0xde, 0xfb, 0xf4, 0xcb, 0xf7, 0x8f, 0xe4
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_pt[] = {
    0xc8, 0xd2, 0x75, 0xf9, 0x19, 0xe1, 0x7d, 0x7f, 0xe6, 0x9c, 0x2a, 0x1f,
    0x58, 0x93, 0x9d, 0xfe, 0x4d, 0x40, 0x37, 0x91, 0xb5, 0xdf, 0x13, 0x10
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_ct[] = {
    0x8a, 0x0f, 0x3d, 0x82, 0x29, 0xe4, 0x8e, 0x74, 0x87, 0xfd, 0x95, 0xa2,
    0x8a, 0xd3, 0x92, 0xc8, 0x0b, 0x36, 0x81, 0xd4, 0xfb, 0xc7, 0xbb, 0xfd
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ccm_tag[] = {
    0x2d, 0xd6, 0xef, 0x1c, 0x45, 0xd4, 0xcc, 0xb7, 0x23, 0xdc, 0x07, 0x44,
    0x14, 0xdb, 0x50, 0x6d
};


/* AES-GCM test data from NIST public test vectors */

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_pt[] = {
    0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
    0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
    0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
    0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
    0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
    0x74, 0x2e,
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_aad[] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_key[] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_iv[] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_ct[] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
};

GLOBAL_REMOVE_IF_UNREFERENCED CONST UINT8 ChaCha20Poly1305_tag[] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

/**
  Validate UEFI-OpenSSL AEAD Ciphers Interfaces.

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptAeadCipher (
  VOID
  )
{
  BOOLEAN  Status;
  UINT8    OutBuffer[1024];
  UINTN    OutBufferSize;
  UINT8    OutTag[1024];
  UINTN    OutTagSize;

  Print (L"\nUEFI-OpenSSL AEAD Testing: ");

  Print (L"\n- AES-CCM Encryption: ");
  OutBufferSize = sizeof(OutBuffer);
  OutTagSize = sizeof(ccm_tag);
  Status = AeadAesCcmEncrypt (
             ccm_key,
             sizeof(ccm_key),
             ccm_nonce,
             sizeof(ccm_nonce),
             ccm_adata,
             sizeof(ccm_adata),
             ccm_pt,
             sizeof(ccm_pt),
             OutTag,
             OutTagSize,
             OutBuffer,
             &OutBufferSize
             );
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(ccm_ct)) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem (OutBuffer, ccm_ct, sizeof(ccm_ct)) != 0) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  } 
  if (CompareMem (OutTag, ccm_tag, sizeof(ccm_tag)) != 0) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  } 
  Print (L"[Pass]");


  Print (L"\n- AES-CCM Decryption: ");
  Status = AeadAesCcmDecrypt (
             ccm_key,
             sizeof(ccm_key),
             ccm_nonce,
             sizeof(ccm_nonce),
             ccm_adata,
             sizeof(ccm_adata),
             ccm_ct,
             sizeof(ccm_ct),
             ccm_tag,
             sizeof(ccm_tag),
             OutBuffer,
             &OutBufferSize
             );
  if (!Status) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(ccm_pt)) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem (OutBuffer, ccm_pt, sizeof(ccm_pt)) != 0) {
    Print (L"[Fail]");
    return EFI_ABORTED;
  }

  Print (L"[Pass]");


  Print(L"\n- AES-GCM Encryption: ");
  OutBufferSize = sizeof(OutBuffer);
  OutTagSize = sizeof(gcm_tag);
  Status = AeadAesGcmEncrypt(
	           gcm_key,
	           sizeof(gcm_key),
	           gcm_iv,
	           sizeof(gcm_iv),
	           gcm_aad,
	           sizeof(gcm_aad),
	           gcm_pt,
	           sizeof(gcm_pt),
	           OutTag,
	           OutTagSize,
	           OutBuffer,
	           &OutBufferSize
             );
  if (!Status) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(gcm_ct)) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  if (CompareMem(OutBuffer, gcm_ct, sizeof(gcm_ct)) != 0) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  if (CompareMem(OutTag, gcm_tag, sizeof(gcm_tag)) != 0) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  Print(L"[Pass]");

  Print(L"\n- AES-GCM Decryption: ");
  Status = AeadAesGcmDecrypt(
	           gcm_key,
	           sizeof(gcm_key),
	           gcm_iv,
	           sizeof(gcm_iv),
	           gcm_aad,
	           sizeof(gcm_aad),
	           gcm_ct,
	           sizeof(gcm_ct),
	           gcm_tag,
	           sizeof(gcm_tag),
	           OutBuffer,
	           &OutBufferSize
             );
  if (!Status) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(gcm_pt)) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }
  if (CompareMem(OutBuffer, gcm_pt, sizeof(gcm_pt)) != 0) {
	  Print(L"[Fail]");
	  return EFI_ABORTED;
  }

  Print(L"[Pass]");


  Print(L"\n- ChaCha20Poly1305 Encryption: ");
  OutBufferSize = sizeof(OutBuffer);
  OutTagSize = sizeof(ChaCha20Poly1305_tag);
  Status = AeadChaCha20Poly1305Encrypt (
             ChaCha20Poly1305_key,
             sizeof(ChaCha20Poly1305_key),
             ChaCha20Poly1305_iv,
             sizeof(ChaCha20Poly1305_iv),
             ChaCha20Poly1305_aad,
             sizeof(ChaCha20Poly1305_aad),
             ChaCha20Poly1305_pt,
             sizeof(ChaCha20Poly1305_pt),
             OutTag,
             OutTagSize,
             OutBuffer,
             &OutBufferSize
             );
  if (!Status) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(ChaCha20Poly1305_ct)) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem(OutBuffer, ChaCha20Poly1305_ct, sizeof(ChaCha20Poly1305_ct)) != 0) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem(OutTag, ChaCha20Poly1305_tag, sizeof(ChaCha20Poly1305_tag)) != 0) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  Print(L"[Pass]");

  Print(L"\n- ChaCha20Poly1305 Decryption: ");
  Status = AeadChaCha20Poly1305Decrypt(
             ChaCha20Poly1305_key,
             sizeof(ChaCha20Poly1305_key),
             ChaCha20Poly1305_iv,
             sizeof(ChaCha20Poly1305_iv),
             ChaCha20Poly1305_aad,
             sizeof(ChaCha20Poly1305_aad),
             ChaCha20Poly1305_ct,
             sizeof(ChaCha20Poly1305_ct),
             ChaCha20Poly1305_tag,
             sizeof(ChaCha20Poly1305_tag),
             OutBuffer,
             &OutBufferSize
           );
  if (!Status) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  if (OutBufferSize != sizeof(ChaCha20Poly1305_pt)) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }
  if (CompareMem(OutBuffer, ChaCha20Poly1305_pt, sizeof(ChaCha20Poly1305_pt)) != 0) {
    Print(L"[Fail]");
    return EFI_ABORTED;
  }

  Print(L"[Pass]");

  Print (L"\n");

  return EFI_SUCCESS;
}
