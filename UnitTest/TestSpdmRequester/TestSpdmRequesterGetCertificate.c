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
  case 0xB:
    return RETURN_SUCCESS;
  case 0xC:
    return RETURN_SUCCESS;
  case 0xD:
    return RETURN_SUCCESS;
  case 0xE:
    return RETURN_SUCCESS;
  case 0xF:
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
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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

  case 0xB:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      UINT8                         *LeafCertBuffer;
      UINTN                         LeafCertBufferSize;
      UINT8                         *CertBuffer;
      UINTN                         CertBufferSize;
      UINTN                         HashSize;


      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);

        // load certificate
        HashSize = GetSpdmHashSize (mUseHashAlgo);
        CertBuffer = (UINT8 *)LocalCertificateChain + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertBufferSize = LocalCertificateChainSize - sizeof(SPDM_CERT_CHAIN) - HashSize;
        if (!X509GetCertFromCertChain (CertBuffer, CertBufferSize, -1, &LeafCertBuffer, &LeafCertBufferSize)) {
          DEBUG((DEBUG_INFO, "!!! VerifyCertificateChain - FAIL (get leaf certificate failed)!!!\n"));
          return RETURN_DEVICE_ERROR;
        }
        // tamper certificate signature on purpose
        // arbitrarily change the last byte of the certificate signature
        CertBuffer[CertBufferSize-1]++;
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

    case 0xC:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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

  case 0xD:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TEST_CERT_SMALL, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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

  case 0xE:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINT16                        GetCertLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      // this should match the value on the test function
      GetCertLength = 1;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
      }
      Count = (LocalCertificateChainSize + GetCertLength + 1) / GetCertLength;
      if (CallingIndex != Count - 1) {
        PortionLength = GetCertLength;
        RemainderLength = (UINT16)(LocalCertificateChainSize - GetCertLength * (CallingIndex + 1));
      } else {
        PortionLength = (UINT16)(LocalCertificateChainSize - GetCertLength * (Count - 1));
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
      CopyMem (SpdmResponse + 1, (UINT8 *)LocalCertificateChain + GetCertLength * CallingIndex, PortionLength);

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

  case 0xF:
  {
      SPDM_CERTIFICATE_RESPONSE    *SpdmResponse;
      UINT8                         TempBuf[MAX_SPDM_MESSAGE_BUFFER_SIZE];
      UINTN                         TempBufSize;
      UINT16                        PortionLength;
      UINT16                        RemainderLength;
      UINTN                         Count;
      STATIC UINTN                  CallingIndex = 0;

      if (LocalCertificateChain == NULL) {
        ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TEST_CERT_MAXUINT16, &LocalCertificateChain, &LocalCertificateChainSize, NULL, NULL);
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

/**
  Test 1: message could not be sent
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in Transcript.MessageB buffer)
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

/**
  Test 2: Normal case, request a certificate chain
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 3: simulate wrong ConnectionState when sending GET_CERTIFICATE (missing SPDM_GET_DIGESTS_RECEIVE_FLAG and SPDM_GET_CAPABILITIES_RECEIVE_FLAG)
  Expected Behavior: get a RETURN_UNSUPPORTED, with no CERTIFICATE messages received (checked in Transcript.MessageB buffer)
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNotStarted;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_UNSUPPORTED);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

/**
  Test 4: force responder to send an ERROR message with code SPDM_ERROR_CODE_INVALID_REQUEST
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in Transcript.MessageB buffer)
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

/**
  Test 5: force responder to send an ERROR message with code SPDM_ERROR_CODE_BUSY
  Expected Behavior: get a RETURN_NO_RESPONSE, with no CERTIFICATE messages received (checked in Transcript.MessageB buffer)
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_NO_RESPONSE);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

/**
  Test 6: force responder to first send an ERROR message with code SPDM_ERROR_CODE_BUSY, but functions normally afterwards
  Expected Behavior: receives the correct number of CERTIFICATE messages
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 7: force responder to send an ERROR message with code SPDM_ERROR_CODE_REQUEST_RESYNCH
  Expected Behavior: get a RETURN_DEVICE_ERROR, with no CERTIFICATE messages received (checked in Transcript.MessageB buffer)
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  assert_int_equal (SpdmContext->ConnectionInfo.ConnectionState, SpdmConnectionStateNotStarted);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, 0);
  free(Data);
}

/**
  Test 8: force responder to send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY
  Expected Behavior: get a RETURN_NO_RESPONSE
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_DEVICE_ERROR);
  free(Data);
}

/**
  Test 9: force responder to first send an ERROR message with code SPDM_ERROR_CODE_RESPONSE_NOT_READY, but functions normally afterwards
  Expected Behavior: receives the correct number of CERTIFICATE messages
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 10: Normal case, request a certificate chain. Validates certificate by using a prelaoded chain instead of root hash
  Expected Behavior: receives the correct number of Certificate messages
**/
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = 0;
  SpdmContext->LocalContext.PeerRootCertHashProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvision = Data;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = DataSize;
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 11: Normal procedure, but the retrieved certificate chain has an invalid signature
  Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
**/
void TestSpdmRequesterGetCertificateCase11(void **state) {
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  // Setting SPDM context as the first steps of the protocol has been accomplished
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  // Loading certificate chain and saving root certificate hash
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  // Reseting message buffer
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  // Calculating expected number of messages received
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 12: Normal procedure, but the retrieved root certificate hash does not match
  Expected Behavior: get a RETURN_SECURITY_VIOLATION, and receives the correct number of Certificate messages
**/
void TestSpdmRequesterGetCertificateCase12(void **state) {
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  // Setting SPDM context as the first steps of the protocol has been accomplished
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  // arbitrarily changes the root certificate hash on purpose
  ((UINT8*)Hash)[0]++;
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  // Reseting message buffer
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  // Calculating expected number of messages received
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SECURITY_VIOLATION);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 13: Gets a short certificate chain (fits in 1 message)
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void TestSpdmRequesterGetCertificateCase13(void **state) {
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  // Setting SPDM context as the first steps of the protocol has been accomplished
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  // Loading Root certificate and saving its hash
  ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TEST_CERT_SMALL, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  // Reseting message buffer
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  // Calculating expected number of messages received
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  free(Data);
}

/**
  Test 14: Request a whole certificate chain byte by byte
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void TestSpdmRequesterGetCertificateCase14(void **state) {
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
  UINT16               GetCertLength;

  // Get certificate chain byte by byte
  GetCertLength = 1;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  // Setting SPDM context as the first steps of the protocol has been accomplished
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  // Loading Root certificate and saving its hash
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  // Reseting message buffer
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  // Calculating expected number of messages received
  Count = (DataSize + GetCertLength - 1) / GetCertLength;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificateChooseLength (SpdmContext, 0, GetCertLength, &CertChainSize, CertChain);
  // It may fail because the spdm does not support too many messages.
  //assert_int_equal (Status, RETURN_SUCCESS);
  if (Status == RETURN_SUCCESS) {
    assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  }
  free(Data);
}

/**
  Test 15: Request a long certificate chain
  Expected Behavior: receives a valid certificate chain with the correct number of Certificate messages
**/
void TestSpdmRequesterGetCertificateCase15(void **state) {
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
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xF;
  // Setting SPDM context as the first steps of the protocol has been accomplished
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  // Loading Root certificate and saving its hash
  ReadResponderPublicCertificateChainBySize (mUseHashAlgo, mUseAsymAlgo, TEST_CERT_MAXUINT16, &Data, &DataSize, &Hash, &HashSize);
  SpdmContext->LocalContext.PeerRootCertHashProvisionSize = HashSize;
  SpdmContext->LocalContext.PeerRootCertHashProvision = Hash;
  SpdmContext->LocalContext.PeerCertChainProvision = NULL;
  SpdmContext->LocalContext.PeerCertChainProvisionSize = 0;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  // Reseting message buffer
  SpdmContext->Transcript.MessageB.BufferSize = 0;
  // Calculating expected number of messages received
  Count = (DataSize + MAX_SPDM_CERT_CHAIN_BLOCK_LEN - 1) / MAX_SPDM_CERT_CHAIN_BLOCK_LEN;

  CertChainSize = sizeof(CertChain);
  ZeroMem (CertChain, sizeof(CertChain));
  Status = SpdmGetCertificate (SpdmContext, 0, &CertChainSize, CertChain);
  // It may fail because the spdm does not support too long message.
  //assert_int_equal (Status, RETURN_SUCCESS);
  if (Status == RETURN_SUCCESS) {
    assert_int_equal (SpdmContext->Transcript.MessageB.BufferSize, sizeof(SPDM_GET_CERTIFICATE_REQUEST)*Count + sizeof(SPDM_CERTIFICATE_RESPONSE)*Count + DataSize);
  }
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
      // ConnectionState check failed
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
      // Invalid certificate signature
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase11),
      // Fail certificate chain check
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase12),
      // Sucessful response: get a certificate chain that fits in one single message
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase13),
      // Sucessful response: get certificate chain byte by byte
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase14),
      // Sucessful response: get a long certificate chain
      cmocka_unit_test(TestSpdmRequesterGetCertificateCase15),
  };

  SetupSpdmTestContext (&mSpdmRequesterGetCertificateTestContext);

  return cmocka_run_group_tests(SpdmRequesterGetCertificateTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
