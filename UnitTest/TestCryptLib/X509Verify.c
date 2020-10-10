/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

RETURN_STATUS
EFIAPI
GetDMTFSubjectAltNameFromBytes (
  IN      CONST UINT8   *Buffer,
  IN      INTN          Len,
  OUT     CHAR8         *NameBuffer,  OPTIONAL
  IN OUT  UINTN         *NameBufferSize,
  OUT     UINT8         *Oid,         OPTIONAL
  IN OUT  UINTN         *OidSize
);

// https://lapo.it/asn1js/#MCQGCisGAQQBgxyCEgEMFkFDTUU6V0lER0VUOjEyMzQ1Njc4OTA
CONST UINT8 SubjectAltNameBuffer1[] = {
0x30, 0x24, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, 0x0C, 0x16,
0x41, 0x43, 0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32, 0x33, 0x34,
0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

// https://lapo.it/asn1js/#MCYGCisGAQQBgxyCEgGgGAwWQUNNRTpXSURHRVQ6MTIzNDU2Nzg5MA
CONST UINT8 SubjectAltNameBuffer2[] = {
0x30, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01, 0xA0, 0x18,
0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A, 0x31, 0x32,
0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

// https://lapo.it/asn1js/#MCigJgYKKwYBBAGDHIISAaAYDBZBQ01FOldJREdFVDoxMjM0NTY3ODkw
CONST UINT8 SubjectAltNameBuffer3[] = {
0x30, 0x28, 0xA0, 0x26, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0x1C, 0x82, 0x12, 0x01,
0xA0, 0x18, 0x0C, 0x16, 0x41, 0x43, 0x4D, 0x45, 0x3A, 0x57, 0x49, 0x44, 0x47, 0x45, 0x54, 0x3A,
0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30
};

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
  UINTN         DMTFOidSize;
  UINT8         DMTFOid[64];
  UINT8         EndCertFrom[64];
  UINTN         EndCertFromLen;
  UINT8         EndCertTo[64];
  UINTN         EndCertToLen;

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
  // Test Three SubjectAltName format
  //
  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = GetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer1, sizeof (SubjectAltNameBuffer1), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  if (RETURN_ERROR(Ret) || CompareMem(DMTFOid, DMTF_OID, sizeof (DMTF_OID)) != 0) {
    Print ("\n  - Retrieving  SubjectAltName1 otherName - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving  SubjectAltName1 otherName = \"%s\" (Size = %d) ", CommonName, CommonNameSize));
    Print ("- [Pass]");
  }

  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = GetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer2, sizeof (SubjectAltNameBuffer2), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  if (RETURN_ERROR(Ret) || CompareMem(DMTFOid, DMTF_OID, sizeof (DMTF_OID)) != 0) {
    Print ("\n  - Retrieving  SubjectAltName2 otherName - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving  SubjectAltName2 otherName = \"%s\" (Size = %d) ", CommonName, CommonNameSize));
    Print ("- [Pass]");
  }

  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = GetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer3, sizeof (SubjectAltNameBuffer3), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  if (RETURN_ERROR(Ret) || CompareMem(DMTFOid, DMTF_OID, sizeof (DMTF_OID)) != 0) {
    Print ("\n  - Retrieving  SubjectAltName3 otherName - [Fail]");
    goto Cleanup;
  } else {
    DEBUG((DEBUG_INFO, "\n  - Retrieving  SubjectAltName3 otherName = \"%s\" (Size = %d) ", CommonName, CommonNameSize));
    Print ("- [Pass]");
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

  //
  // Check X509 Validity
  //
  Status = X509SPDMCertificateCheck(TestEndCert, TestEndCertLen);
  if (!Status) {
    Print ("\n- X509 Check SPDM Certificate - [Fail]");
    goto Cleanup;
  } else {
    Print ("\n- X509 Check SPDM Certificate - [Pass]");
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
