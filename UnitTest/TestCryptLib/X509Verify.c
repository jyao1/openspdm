/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

STATIC CONST UINT8 OID_subjectAltName[] = {
  0x55, 0x1D, 0x11
};

/**
  Validate UEFI-Crypto  X509 certificate Verify

  @retval  EFI_SUCCESS  Validation succeeded.
  @retval  EFI_ABORTED  Validation failed.

**/
EFI_STATUS
ValidateCryptX509 (
  CHAR8 *Path,
  UINTN Len
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
  UINT8         EndCertFrom[64];
  UINTN         EndCertFromLen;
  UINT8         EndCertTo[64];
  UINTN         EndCertToLen;
  UINT8         DateTime1[64];
  UINT8         DateTime2[64];
  EFI_STATUS    EfiStatus;

  EfiStatus = EFI_ABORTED;
  TestCert = NULL;
  TestCACert = NULL;
  TestBundleCert = NULL;
  TestEndCert = NULL;
  CHAR8         FileNameBuffer[1024];

  ZeroMem(FileNameBuffer, 1024);
  CopyMem(FileNameBuffer, Path, Len);
  CopyMem(FileNameBuffer+Len - 1, "/inter.cert.der", sizeof("/inter.cert.der"));
  Status = ReadInputFile (FileNameBuffer, (VOID **)&TestCert, &TestCertLen);
  if (!Status) {
    goto Cleanup;
  }

  ZeroMem(FileNameBuffer, 1024);
  CopyMem(FileNameBuffer, Path, Len);
  CopyMem(FileNameBuffer+Len - 1, "/ca.cert.der", sizeof("/ca.cert.der"));
  Status = ReadInputFile (FileNameBuffer, (VOID **)&TestCACert, &TestCACertLen);
  if (!Status) {
    goto Cleanup;
  }

  ZeroMem(FileNameBuffer, 1024);
  CopyMem(FileNameBuffer, Path, Len);
  CopyMem(FileNameBuffer+Len - 1, "/bundle_requester.certchain.der", sizeof("/bundle_requester.certchain.der"));
  Status = ReadInputFile (FileNameBuffer, (VOID **)&TestBundleCert, &TestBundleCertLen);
  if (!Status) {
    goto Cleanup;
  }

  ZeroMem(FileNameBuffer, 1024);
  CopyMem(FileNameBuffer, Path, Len);
  CopyMem(FileNameBuffer+Len - 1, "/end_requester.cert.der", sizeof("/end_requester.cert.der"));
  Status = ReadInputFile (FileNameBuffer, (VOID **)&TestEndCert, &TestEndCertLen);
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
  Asn1BufferLen = 1024;
  ZeroMem (Asn1Buffer, Asn1BufferLen);
  Ret = X509GetExtensionData (
    TestEndCert, TestEndCertLen,
    (UINT8 *)OID_subjectAltName, sizeof (OID_subjectAltName),
    Asn1Buffer, &Asn1BufferLen);
  if (RETURN_ERROR(Ret)) {
    Print ("\n  - Retrieving  SubjectAltName otherName - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving  SubjectAltName (Size = %d) ", Asn1BufferLen));
    Print ("- [Pass]");
  }

  //
  // Get X509 Validity
  //
  EndCertFromLen = 64;
  EndCertToLen = 64;
  Status = X509GetValidity (TestEndCert, TestEndCertLen, EndCertFrom, &EndCertFromLen, EndCertTo, &EndCertToLen);
  if (!Status) {
    Print ("\n  - Retrieving Validity - [Fail]");
    goto Cleanup;
  } else {
    Print ("\n  - Retrieving Validity - [Pass]");
  }

  Asn1BufferLen = 64;
  Ret = X509SetDateTime("19700101000000Z", DateTime1, &Asn1BufferLen);
  if ((Ret == RETURN_SUCCESS) && (Asn1BufferLen != 0)) {
    Print ("\n  - Set DateTime - [Pass]");
  } else {
    Print ("\n  - Set DateTime - [Fail]");
    goto Cleanup;
  }

  Asn1BufferLen = 64;
  Ret = X509SetDateTime("19700201000000Z", DateTime2, &Asn1BufferLen);
  if ((Ret == RETURN_SUCCESS) && (Asn1BufferLen != 0)) {
    Print ("\n  - Set DateTime - [Pass]");
  } else {
    Print ("\n  - Set DateTime - [Fail]");
    goto Cleanup;
  }

  if (X509CompareDateTime(DateTime1, DateTime2) < 0) {
    Print ("\n  - Compare DateTime - [Pass]");
  } else {
    Print ("\n  - Compare DateTime- [Fail]");
    goto Cleanup;
  }

  Print ("\n");
  EfiStatus = EFI_SUCCESS;

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
  return EfiStatus;
}
