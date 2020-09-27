/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

CONST UINT8 DMTF_OID[] = {
  0x2B, 0x06, 0x01, 0x4, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01
};

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
  BOOLEAN       Status;
  UINT8         *LeafCert;
  UINTN         LeafCertLen;
  UINT8         *TestCert;
  UINTN         TestCertLen;
  UINT8         *TestCACert;
  UINTN         TestCACertLen;
  UINT8         *TestBundleCert;
  UINTN         TestBundleCertLen;
  UINT8         *TestEndCert;
  UINTN         TestEndCertLen;
  UINTN         SubjectSize;
  UINT8         *Subject;
  UINTN         CommonNameSize;
  CHAR8         CommonName[64];
  RETURN_STATUS Ret;
  UINTN         CertVersion;
  UINT8         Asn1Buffer[1024];
  UINTN         Asn1BufferLen;
  UINTN         DMTFOidSize;
  UINT8         DMTFOid[64];

  TestCert = NULL;
  TestCACert = NULL;
  TestBundleCert = NULL;
  TestEndCert = NULL;

  Status = ReadInputFile ("test/inter.cert.der", (VOID **)&TestCert, &TestCertLen);
  if (!Status) {
    goto Cleanup;
  }
  Status = ReadInputFile ("test/ca.cert.der", (VOID **)&TestCACert, &TestCACertLen);
  if (!Status) {
    goto Cleanup;
  }
  Status = ReadInputFile ("test/bundle_requester.certchain.der", (VOID **)&TestBundleCert, &TestBundleCertLen);
  if (!Status) {
    goto Cleanup;
  }
  Status = ReadInputFile ("test/end_requester.cert.der", (VOID **)&TestEndCert, &TestEndCertLen);
  if (!Status) {
    goto Cleanup;
  }

  //
  // X509 Certificate Verification.
  //
  Print ("\n- X509 Certificate Verification with Trusted CA ...");
  Status = X509VerifyCert (TestCert, TestCertLen, TestCACert, TestCACertLen);
  if (!Status) {
    Print ("[Fail]\n");
    goto Cleanup;
  } else {
    Print ("[Pass]\n");
  }

  //
  // X509 Certificate Chain Verification.
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain Verification ... "));
  Status = X509VerifyCertChain((UINT8 *)TestCACert, TestCACertLen, (UINT8 *)TestBundleCert, TestBundleCertLen);
  if (!Status) {
    Print ("[Fail]\n");
    goto Cleanup;
  } else {
    Print ("[Pass]\n");
  }

  //
  // X509 Get leaf certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get leaf certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, -1, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (LeafCertLen != TestEndCertLen) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (CompareMem (LeafCert, TestEndCert, LeafCertLen) != 0) {
    Print ("[Fail]\n");
    goto Cleanup;
  } else {
    Print ("[Pass]\n");
  }

  //
  // X509 Get leaf certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get leaf certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, 2, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (LeafCertLen != TestEndCertLen) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (CompareMem (LeafCert, TestEndCert, LeafCertLen) != 0) {
    Print ("[Fail]\n");
    goto Cleanup;
  } else {
    Print ("[Pass]\n");
  }

  //
  // X509 Get root certificate from CertChain Verificate
  //
  DEBUG((DEBUG_INFO, "- X509 Certificate Chain get root certificate Verification ... "));
  Status = X509GetCertFromCertChain(TestBundleCert, TestBundleCertLen, 0, &LeafCert, &LeafCertLen);
  if (!Status) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (LeafCertLen != TestCACertLen) {
    Print ("[Fail]\n");
    goto Cleanup;
  }
  if (CompareMem (LeafCert, TestCACert, LeafCertLen) != 0) {
    Print ("[Fail]\n");
    goto Cleanup;
  } else {
    Print ("[Pass]\n");
  }


  //
  // X509 Certificate Subject Retrieving.
  //
  Print ("- X509 Certificate Subject Bytes Retrieving ... ");
  SubjectSize = 0;
  Status  = X509GetSubjectName (TestCert, TestCertLen, NULL, &SubjectSize);
  Subject = (UINT8 *)AllocatePool (SubjectSize);
  Status  = X509GetSubjectName (TestCert, TestCertLen, Subject, &SubjectSize);
  FreePool(Subject);
  if (!Status) {
    Print ("[Fail]");
    goto Cleanup;
  } else {
    Print ("[Pass]");
  }

  Print ("\n- X509 Certificate Context Retrieving ... ");
  //
  // Get CommonName from X509 Certificate Subject
  //
  CommonNameSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  Ret = X509GetCommonName (TestCert, TestCertLen, CommonName, &CommonNameSize);
  if (RETURN_ERROR (Ret)) {
    Print ("\n  - Retrieving Common Name - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving Common Name = \"%s\" (Size = %d)", CommonName, CommonNameSize));
    Print(" - [PASS]");
  }

  //
  // Get Issuer OrganizationName from X509 Certificate Subject
  //
  CommonNameSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  Ret = X509GetOrganizationName (TestCert, TestCertLen, CommonName, &CommonNameSize);
  if (Ret != RETURN_NOT_FOUND) {
    Print ("\n  - Retrieving Oraganization Name - [Fail]");
    goto Cleanup;
  } else {
    Print ("\n  - Retrieving Oraganization Name - [PASS]");
  }

  //
  // Get Version from X509 Certificate
  //
  CertVersion = 0;
  Ret = X509GetVersion(TestCert, TestCertLen, &CertVersion);
  if (RETURN_ERROR (Ret)) {
    Print ("\n  - Retrieving Version - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving Version = %d - ", CertVersion));
    Print ("[Pass]");
  }

  //
  // Get Serial from X509 Certificate
  //
  Asn1BufferLen = 1024;
  ZeroMem(Asn1Buffer, Asn1BufferLen);
  Ret = X509GetSerialNumber(TestCert, TestCertLen, Asn1Buffer, &Asn1BufferLen);
  if (RETURN_ERROR (Ret)) {
    Print ("\n  - Retrieving SerialNumber - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving SerialNumber = %d - ", *((UINT64*)Asn1Buffer)));
    Print ("[Pass]");
  }

  //
  // X509 Certificate Subject Retrieving.
  //
  Print ("\n  - Retrieving issuer Bytes ... ");
  SubjectSize = 0;
  Status  = X509GetIssuerName (TestCert, TestCertLen, NULL, &SubjectSize);
  Subject = (UINT8 *)AllocatePool (SubjectSize);
  Status  = X509GetIssuerName (TestCert, TestCertLen, Subject, &SubjectSize);
  FreePool(Subject);
  if (!Status) {
    Print ("[Fail]");
    goto Cleanup;
  } else {
    Print (" - [Pass]");
  }

  //
  // Get Issuer CommonName from X509 Certificate Subject
  //
  CommonNameSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  Ret = X509GetIssuerCommonName (TestCert, TestCertLen, CommonName, &CommonNameSize);
  if (RETURN_ERROR (Ret)) {
    Print ("\n  - Retrieving Issuer Common Name - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving Issuer Common Name = \"%s\" (Size = %d) - ", CommonName, CommonNameSize));
    Print ("[Pass]");
  }

  //
  // Get Issuer OrganizationName from X509 Certificate Subject
  //
  CommonNameSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  Ret = X509GetIssuerOrganizationName (TestCert, TestCertLen, CommonName, &CommonNameSize);
  if (Ret != RETURN_NOT_FOUND) {
    Print ("\n  - Retrieving Issuer Oraganization Name - [Fail]");
    goto Cleanup;
  } else {
    Print ("\n  - Retrieving Issuer Oraganization Name - [Pass]");
  }

  //
  // Get X509GetSubjectAltName
  //
  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = X509GetDMTFSubjectAltName(TestEndCert, TestEndCertLen, CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  if (RETURN_ERROR(Ret) || CompareMem(DMTFOid, DMTF_OID, sizeof (DMTF_OID)) != 0) {
    Print ("\n  - Retrieving  SubjectAltName otherName - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving  SubjectAltName otherName = \"%s\" (Size = %d) ", CommonName, CommonNameSize));
    Print ("- [Pass]");
  }

  Print ("\n");
  return EFI_SUCCESS;

Cleanup:
  if (TestCert != NULL) {
    free (TestCert);
  }
  if (TestCACert != NULL) {
    free (TestCACert);
  }
  if (TestBundleCert != NULL) {
    free (TestBundleCert);
  }
  if (TestEndCert != NULL) {
    free (TestEndCert);
  }
  return EFI_ABORTED;
}
