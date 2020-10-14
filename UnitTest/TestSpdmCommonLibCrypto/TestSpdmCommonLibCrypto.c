/**
@file
SpdmCommonLibCryptoLib Tests

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"

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


void TestSpdmCommonLibCrypto_SpdmGetDMTFSubjectAltNameFromBytes(void **state) {
  UINTN         CommonNameSize;
  CHAR8         CommonName[64];
  UINTN         DMTFOidSize;
  UINT8         DMTFOid[64];
  RETURN_STATUS Ret;

  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = SpdmGetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer1, sizeof (SubjectAltNameBuffer1), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");

  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = SpdmGetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer2, sizeof (SubjectAltNameBuffer2), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");

  CommonNameSize = 64;
  DMTFOidSize = 64;
  ZeroMem (CommonName, CommonNameSize);
  ZeroMem (DMTFOid, DMTFOidSize);
  Ret = SpdmGetDMTFSubjectAltNameFromBytes(SubjectAltNameBuffer3, sizeof (SubjectAltNameBuffer3), CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");
}

void TestSpdmCommonLibCrypto_SpdmGetDMTFSubjectAltName(void **state) {
  UINTN         CommonNameSize;
  CHAR8         CommonName[64];
  UINTN         DMTFOidSize;
  UINT8         DMTFOid[64];
  UINT8         *FileBuffer;
  UINTN         FileBufferSize;
  RETURN_STATUS Ret;
  BOOLEAN       Status;
  Status = ReadInputFile ("Rsa2048/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  DMTFOidSize = 64;
  CommonNameSize = 64;
  Ret = SpdmGetDMTFSubjectAltName(FileBuffer, FileBufferSize, CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");

  Status = ReadInputFile ("Rsa3072/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  DMTFOidSize = 64;
  CommonNameSize = 64;
  Ret = SpdmGetDMTFSubjectAltName(FileBuffer, FileBufferSize, CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");

  Status = ReadInputFile ("EcP256/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  DMTFOidSize = 64;
  CommonNameSize = 64;
  Ret = SpdmGetDMTFSubjectAltName(FileBuffer, FileBufferSize, CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");

  Status = ReadInputFile ("EcP384/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  DMTFOidSize = 64;
  CommonNameSize = 64;
  Ret = SpdmGetDMTFSubjectAltName(FileBuffer, FileBufferSize, CommonName, &CommonNameSize, DMTFOid, &DMTFOidSize);
  assert_int_equal((int)Ret, RETURN_SUCCESS);
  assert_memory_equal(DMTF_OID, DMTFOid, sizeof (DMTF_OID));
  assert_string_equal(CommonName, "ACME:WIDGET:1234567890");
}

void TestSpdmCommonLibCrypto_SpdmX509CertificateCheck(void **state) {
  BOOLEAN       Status;
  UINT8         *FileBuffer;
  UINTN         FileBufferSize;
  Status = ReadInputFile ("Rsa2048/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  Status = SpdmX509CertificateCheck(FileBuffer, FileBufferSize);
  assert_true(Status);

  Status = ReadInputFile ("Rsa3072/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  Status = SpdmX509CertificateCheck(FileBuffer, FileBufferSize);
  assert_true(Status);
  Status = ReadInputFile ("EcP256/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  Status = SpdmX509CertificateCheck(FileBuffer, FileBufferSize);
  assert_true(Status);

  Status = ReadInputFile ("EcP384/end_requester.cert.der", (VOID **)&FileBuffer, &FileBufferSize);
  assert_true(Status);
  Status = SpdmX509CertificateCheck(FileBuffer, FileBufferSize);
  assert_true(Status);

}

int Setup(void **state)
{
  return 0;
}

int TearDown(void **state)
{
  return 0;
}

int SpdmCommonLibCryptoTestMain(void) {
  const struct CMUnitTest SpdmCommonLibCryptoTests[] = {
      cmocka_unit_test(TestSpdmCommonLibCrypto_SpdmGetDMTFSubjectAltNameFromBytes),
      cmocka_unit_test(TestSpdmCommonLibCrypto_SpdmGetDMTFSubjectAltName),
      cmocka_unit_test(TestSpdmCommonLibCrypto_SpdmX509CertificateCheck)
  };

  return cmocka_run_group_tests(SpdmCommonLibCryptoTests, Setup, TearDown);
}

int main(void) {
  SpdmCommonLibCryptoTestMain();
  return 0;
}
