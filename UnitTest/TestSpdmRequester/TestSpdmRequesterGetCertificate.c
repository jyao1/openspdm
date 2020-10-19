/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmRequesterLibInternal.h>

STATIC VOID                  *LocalCertificateChain;
STATIC UINTN                 LocalCertificateChainSize;

RETURN_STATUS
EFIAPI
SpdmRequesterGetCertificateTestSendMessage (
  IN     VOID                    *SpdmContext,
  IN     UINTN                   RequestSize,
  IN     VOID                    *Request,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;
  case 0x2:
    return RETURN_SUCCESS;
  case 0x3:
    return RETURN_SUCCESS;
  case 0x4:
    return RETURN_SUCCESS;
  case 0x5:
    return RETURN_SUCCESS;
  case 0x6:
    return RETURN_SUCCESS;
  case 0x7:
    return RETURN_SUCCESS;
  case 0x8:
    return RETURN_SUCCESS;
  case 0x9:
    return RETURN_SUCCESS;
  case 0xA:
    return RETURN_SUCCESS;
  default:
    return RETURN_DEVICE_ERROR;
  }
}

RETURN_STATUS
EFIAPI
SpdmRequesterGetCertificateTestReceiveMessage (
  IN     VOID                    *SpdmContext,
  IN OUT UINTN                   *ResponseSize,
  IN OUT VOID                    *Response,
  IN     UINT64                  Timeout
  )
{
  SPDM_TEST_CONTEXT       *SpdmTestContext;

  SpdmTestContext = GetSpdmTestContext ();
  switch (SpdmTestContext->CaseId) {
  case 0x1:
    return RETURN_DEVICE_ERROR;

  case 0x2:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (&LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
      if (CallingIndex != Count - 1) {
        PortionLength = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
        RemainderLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (Count - 1));
        RemainderLength = 0;
      }

      TempBufSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + PortionLength;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->PortionLength = PortionLength;
      SpdmResponse->RemainderLength = RemainderLength;
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + MAX_SPDM_CERT_CHAIN_BLOCK_LEN * CallingIndex, PortionLength);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

      CallingIndex++;
      if (CallingIndex == Count) {
        CallingIndex = 0;
        free (LocalCertificateChain);
        LocalCertificateChain = NULL;
        LocalCertificateChainSize = 0;
      }
  }
    return RETURN_SUCCESS;

  case 0x3:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (&LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
      if (CallingIndex != Count - 1) {
        PortionLength = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
        RemainderLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (Count - 1));
        RemainderLength = 0;
      }

      TempBufSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + PortionLength;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->PortionLength = PortionLength;
      SpdmResponse->RemainderLength = RemainderLength;
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + MAX_SPDM_CERT_CHAIN_BLOCK_LEN * CallingIndex, PortionLength);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

      CallingIndex++;
      if (CallingIndex == Count) {
        CallingIndex = 0;
        free (LocalCertificateChain);
        LocalCertificateChain = NULL;
        LocalCertificateChainSize = 0;
      }
  }
    return RETURN_SUCCESS;

  case 0x4:
  {
    SPDM_ERROR_RESPONSE    SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_INVALID_REQUEST;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x5:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x6:
  {
    STATIC UINTN SubIndex1 = 0;
    if (SubIndex1 == 0) {
      SPDM_ERROR_RESPONSE  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_BUSY;
      SpdmResponse.Header.Param2 = 0;
      SubIndex1 ++;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex1 == 1) {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (&LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
      if (CallingIndex != Count - 1) {
        PortionLength = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
        RemainderLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (Count - 1));
        RemainderLength = 0;
      }

      TempBufSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + PortionLength;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->PortionLength = PortionLength;
      SpdmResponse->RemainderLength = RemainderLength;
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + MAX_SPDM_CERT_CHAIN_BLOCK_LEN * CallingIndex, PortionLength);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

      CallingIndex++;
      if (CallingIndex == Count) {
        CallingIndex = 0;
        free (LocalCertificateChain);
        LocalCertificateChain = NULL;
        LocalCertificateChainSize = 0;
      }
    }
  }
    return RETURN_SUCCESS;

  case 0x7:
  {
    SPDM_ERROR_RESPONSE  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_REQUEST_RESYNCH;
    SpdmResponse.Header.Param2 = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x8:
  {
    SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

    SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
    SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
    SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
    SpdmResponse.Header.Param2 = 0;
    SpdmResponse.ExtendErrorData.RDTExponent = 1;
    SpdmResponse.ExtendErrorData.RDTM = 1;
    SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_CERTIFICATE;
    SpdmResponse.ExtendErrorData.Token = 0;

    SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
  }
    return RETURN_SUCCESS;

  case 0x9:
  {
    STATIC UINTN SubIndex2 = 0;
    if (SubIndex2 == 0) {
      SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  SpdmResponse;

      SpdmResponse.Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse.Header.RequestResponseCode = SPDM_ERROR;
      SpdmResponse.Header.Param1 = SPDM_ERROR_CODE_RESPONSE_NOT_READY;
      SpdmResponse.Header.Param2 = 0;
      SpdmResponse.ExtendErrorData.RDTExponent = 1;
      SpdmResponse.ExtendErrorData.RDTM = 1;
      SpdmResponse.ExtendErrorData.RequestCode = SPDM_GET_CERTIFICATE;
      SpdmResponse.ExtendErrorData.Token = 1;
      SubIndex2 ++;

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, sizeof(SpdmResponse), &SpdmResponse, ResponseSize, Response);
    } else if (SubIndex2 == 1) {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (&LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
      if (CallingIndex != Count - 1) {
        PortionLength = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
        RemainderLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (Count - 1));
        RemainderLength = 0;
      }

      TempBufSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + PortionLength;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->PortionLength = PortionLength;
      SpdmResponse->RemainderLength = RemainderLength;
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + MAX_SPDM_CERT_CHAIN_BLOCK_LEN * CallingIndex, PortionLength);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

      CallingIndex++;
      if (CallingIndex == Count) {
        CallingIndex = 0;
        free (LocalCertificateChain);
        LocalCertificateChain = NULL;
        LocalCertificateChainSize = 0;
      }
    }
  }
    return RETURN_SUCCESS;

  case 0xA:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (&LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN + 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
      if (CallingIndex != Count - 1) {
        PortionLength = MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
        RemainderLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN * (Count - 1));
        RemainderLength = 0;
      }

      TempBufSize = sizeof(SPDM_CERTIFICATE_RESPONSE) + PortionLength;
      SpdmResponse = (VOID *)TempBuf;

      SpdmResponse->Header.SPDMVersion = SPDM_MESSAGE_VERSION_10;
      SpdmResponse->Header.RequestResponseCode = SPDM_CERTIFICATE;
      SpdmResponse->Header.Param1 = 0;
      SpdmResponse->Header.Param2 = 0;
      SpdmResponse->PortionLength = PortionLength;
      SpdmResponse->RemainderLength = RemainderLength;
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + MAX_SPDM_CERT_CHAIN_BLOCK_LEN * CallingIndex, PortionLength);

      SpdmTransportTestEncodeMessage (SpdmContext, NULL, FALSE, FALSE, TempBufSize, TempBuf, ResponseSize, Response);

      CallingIndex++;
      if (CallingIndex == Count) {
        CallingIndex = 0;
        free (LocalCertificateChain);
        LocalCertificateChain = NULL;
        LocalCertificateChainSize = 0;
      }
  }
    return RETURN_SUCCESS;

  default:
    return RETURN_DEVICE_ERROR;
  }
}

void TestSpdmRequesterGetCertificateCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  UINTN                Count;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->SpdmCmdReceiveState = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;
  
  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  UINTN                Count;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->SpdmCmdReceiveState, 0);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  UINTN                Count;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;   
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

void TestSpdmRequesterGetCertificateCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                CertChainSize;
  UINT8                CertChain[MAX_SPDM_CERT_CHAIN_SIZE];
  VOID                 *Data;
  UINTN                DataSize;
  VOID                 *Hash;
  UINTN                HashSize;
  UINTN                Count;

  SpdmTestContext = *state;
  SpdmContext = &SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_DIGESTS_RECEIVE_FLAG;
  SpdmContext->SpdmCmdReceiveState |= SPDM_GET_CAPABILITIES_RECEIVE_FLAG;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (&Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = 0;
  SpdmContext->LocalContext.PeerRootCertHashProvision = NULL;   
  SpdmContext->LocalContext.PeerCertChainProvision = Data;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = DataSize;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = USE_HASH_ALGO;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

SPDM_TEST_CONTEXT       mSpdmRequesterGetCertificateTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  SpdmRequesterGetCertificateTestSendMessage,
  SpdmRequesterGetCertificateTestReceiveMessage,
};

int SpdmRequesterGetCertificateTestMain(void) {
  const struct CMUnitTest SpdmRequesterGetCertificateTests[] = {
      // SendRequest failed
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase1),
      // Successful response: check root certificate hash
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase2),
      // SpdmCmdReceiveState check failed
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase3),
      // Error response: SPDM_ERROR_CODE_INVALID_REQUEST
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase4),
      // Always SPDM_ERROR_CODE_BUSY
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase5),
      // SPDM_ERROR_CODE_BUSY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase6),
      // Error response: SPDM_ERROR_CODE_REQUEST_RESYNCH
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase7),
      // Always SPDM_ERROR_CODE_RESPONSE_NOT_READY
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase8),
      // SPDM_ERROR_CODE_RESPONSE_NOT_READY + Successful response
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase9),
      // Successful response: check certificate chain
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase10),
  };
  
  SetupSpdmTestContext (&mSpdmRequesterGetCertificateTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetCertificateTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
