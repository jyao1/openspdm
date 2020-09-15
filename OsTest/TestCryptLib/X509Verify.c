
#include "Cryptest.h"

/**
  Validate UEFI-Crypto  X509 certificate Verify

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptX509 (
  VOID
  )
{
  INT32 Status;
  UINT8 *LeafCert;
  UINTN LeafCertLen;
  UINT8 *TestCert;
  UINTN TestCertLen;
  UINT8 *TestCACert;
  UINTN TestCACertLen;
  UINT8 *TestBundleCert;
  UINTN TestBundleCertLen;
  UINT8 *TestEndCert;
  UINTN TestEndCertLen;


  Status = ReadInputFile ("test\\inter.cert.der", &TestCert, &TestCertLen);
  Status = ReadInputFile ("test\\ca.cert.der", &TestCACert, &TestCACertLen);
  Status = ReadInputFile ("test\\bundle_requester.certchain.der", &TestBundleCert, &TestBundleCertLen);
  Status = ReadInputFile ("test\\end_requester.cert.der", &TestEndCert, &TestEndCertLen);

  //
  // X509 Certificate Verification.
  //
  Print (L"\n- X509 Certificate Verification with Trusted CA ...");
  Status = X509VerifyCert (TestCert, TestCertLen, TestCACert, TestCACertLen);
  if (!Status) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  //
  // X509 Certificate Chain Verification.
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain Verification ... "));
  Status = X509VerifyCertChain((UINT8 *)TestCACert, TestCACertLen, (UINT8 *)TestBundleCert, TestBundleCertLen);
  if (!Status) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  //
  // X509 Get leaf certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get leaf certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, -1, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (LeafCertLen != TestEndCertLen) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (CompareMem (LeafCert, TestEndCert, LeafCertLen) != 0) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  //
  // X509 Get leaf certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get leaf certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, 2, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (LeafCertLen != TestEndCertLen) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (CompareMem (LeafCert, TestEndCert, LeafCertLen) != 0) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }

  //
  // X509 Get root certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get root certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, 0, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (LeafCertLen != TestCACertLen) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  }
  if (CompareMem (LeafCert, TestCACert, LeafCertLen) != 0) {
    Print (L"[Fail]\n");
    return EFI_ABORTED;
  } else {
    Print (L"[Pass]\n");
  }


  return EFI_SUCCESS;
}
