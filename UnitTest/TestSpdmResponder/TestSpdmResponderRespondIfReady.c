/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmUnitTest.h"
#include <SpdmResponderLibInternal.h>
#include <SpdmSecuredMessageLibInternal.h>

#define MyTestToken           0x30
#define MyWrongTestToken      0x2F

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest1 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest1Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest2 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_CERTIFICATE,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest2Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest3 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_CHALLENGE,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest3Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest4 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_MEASUREMENTS,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest4Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest5 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_KEY_EXCHANGE,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest5Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest6 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_FINISH,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest6Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest7 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_PSK_EXCHANGE,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest7Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest8 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_PSK_FINISH,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest8Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest9 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest9Size = MAX_SPDM_MESSAGE_BUFFER_SIZE; //wrong size

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest10 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_DIGESTS,
    MyWrongTestToken //wrong token
  },
};
UINTN mSpdmRespondIfReadyRequest10Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_RESPONSE_IF_READY_REQUEST    mSpdmRespondIfReadyRequest11 = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_RESPOND_IF_READY,
    SPDM_GET_CERTIFICATE, //wrong original request code
    MyTestToken
  },
};
UINTN mSpdmRespondIfReadyRequest11Size = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_DIGESTS_REQUEST    mSpdmGetDigestRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_DIGESTS,
    0,
    0
  },
};
UINTN mSpdmGetDigestRequestSize = sizeof(SPDM_MESSAGE_HEADER);

SPDM_GET_CERTIFICATE_REQUEST    mSpdmGetCertificateRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_CERTIFICATE,
    0,
    0
  },
  0,
  MAX_SPDM_CERT_CHAIN_BLOCK_LEN
};
UINTN mSpdmGetCertificateRequestSize = sizeof(mSpdmGetCertificateRequest);

SPDM_CHALLENGE_REQUEST    mSpdmChallengeRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_CHALLENGE,
    0,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH
  },
};
UINTN mSpdmChallengeRequestSize = sizeof(mSpdmChallengeRequest);

SPDM_GET_MEASUREMENTS_REQUEST    mSpdmGetMeasurementsRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_GET_MEASUREMENTS,
    0,
    SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS
  },
};
UINTN mSpdmGetMeasurementsRequestSize = sizeof(SPDM_MESSAGE_HEADER);

#pragma pack(1)

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               ReqSessionID;
  UINT16               Reserved;
  UINT8                RandomData[SPDM_RANDOM_DATA_SIZE];
  UINT8                ExchangeData[MAX_DHE_KEY_SIZE];
  UINT16               OpaqueLength;
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_KEY_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                Signature[MAX_ASYM_KEY_SIZE];
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_FINISH_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT16               ReqSessionID;
  UINT16               PSKHintLength;
  UINT16               RequesterContextLength;
  UINT16               OpaqueLength;
  UINT8                PSKHint[MAX_SPDM_PSK_HINT_LENGTH];
  UINT8                RequesterContext[DEFAULT_CONTEXT_LENGTH];
  UINT8                OpaqueData[MAX_SPDM_OPAQUE_DATA_SIZE];
} SPDM_PSK_EXCHANGE_REQUEST_MINE;

typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  UINT8                VerifyData[MAX_HASH_SIZE];
} SPDM_PSK_FINISH_REQUEST_MINE;

#pragma pack()

SPDM_KEY_EXCHANGE_REQUEST_MINE    mSpdmKeyExchangeRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_KEY_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmKeyExchangeRequestSize = sizeof(mSpdmKeyExchangeRequest);

SPDM_FINISH_REQUEST_MINE    mSpdmFinishRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_FINISH,
    0,
    0
  },
};
UINTN mSpdmFinishRequestSize = sizeof(mSpdmFinishRequest);

SPDM_PSK_EXCHANGE_REQUEST_MINE    mSpdmPskExchangeRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_EXCHANGE,
    SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
    0
  },
};
UINTN mSpdmPskExchangeRequestSize = sizeof(mSpdmPskExchangeRequest);

SPDM_PSK_FINISH_REQUEST_MINE    mSpdmPskFinishRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_PSK_FINISH,
    0,
    0
  },
};
UINTN mSpdmPskFinishRequestSize = sizeof(mSpdmPskFinishRequest);

SPDM_END_SESSION_REQUEST    mSpdmEndSessionRequest = {
  {
    SPDM_MESSAGE_VERSION_11,
    SPDM_END_SESSION,
    0,
    0
  }
};
UINTN mSpdmEndSessionRequestSize = sizeof(mSpdmEndSessionRequest);

STATIC UINT8                  LocalCertificateChain[MAX_SPDM_MESSAGE_BUFFER_SIZE];

STATIC
VOID
SpdmSecuredMessageSetRequestFinishedKey (
  IN VOID                         *SpdmSecuredMessageContext,
  IN VOID                         *Key,
  IN UINTN                        KeySize
  )
{
  SPDM_SECURED_MESSAGE_CONTEXT           *SecuredMessageContext;

  SecuredMessageContext = SpdmSecuredMessageContext;
  ASSERT (KeySize == SecuredMessageContext->HashSize);
  CopyMem (SecuredMessageContext->HandshakeSecret.RequestFinishedKey, Key, SecuredMessageContext->HashSize);
}

/**
  Test 1: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_DIGESTS could not be processed.
  Expected behavior: the responder accepts the request and produces a valid DIGESTS
  response message.
**/
void TestSpdmResponderRespondIfReadyCase1(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x1;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;

  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check DIGESTS response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest1Size, &mSpdmRespondIfReadyRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_DIGESTS_RESPONSE) + GetSpdmHashSize(SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_DIGESTS);
}

/**
  Test 2: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_CERTIFICATE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid CERTIFICATE
  response message.
**/
void TestSpdmResponderRespondIfReadyCase2(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CERTIFICATE_RESPONSE *SpdmResponse; //response to the original request (CERTIFICATE)
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x2;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_CERTIFICATE)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAfterDigests;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;

  SpdmContext->LastSpdmRequestSize = mSpdmGetCertificateRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetCertificateRequest, mSpdmGetCertificateRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_CERTIFICATE;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check CERTIFICATE response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest2Size, &mSpdmRespondIfReadyRequest2, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CERTIFICATE_RESPONSE) + MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CERTIFICATE);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->PortionLength, MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  assert_int_equal (SpdmResponse->RemainderLength, DataSize - MAX_SPDM_CERT_CHAIN_BLOCK_LEN);
  free(Data);
}

/**
  Test 3: receiving a correct RESPOND_IF_READY from the requester, after a 
  CHALLENGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid CHALLENGE_AUTH
  response message.
**/
void TestSpdmResponderRespondIfReadyCase3(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_CHALLENGE_AUTH_RESPONSE *SpdmResponse; //response to the original request (CHALLENGE_AUTH)
  VOID                 *Data;
  UINTN                DataSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x3;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (CHALLENGE)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.OpaqueChallengeAuthRspSize = 0;

  SpdmContext->LastSpdmRequestSize = mSpdmChallengeRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmChallengeRequest, mSpdmChallengeRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_CHALLENGE;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check CHALLENGE response
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmChallengeRequest.Nonce);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest3Size, &mSpdmRespondIfReadyRequest3, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + GetSpdmHashSize (mUseHashAlgo) + SPDM_NONCE_SIZE + 0 + sizeof(UINT16) + 0 + GetSpdmAsymSignatureSize (mUseAsymAlgo));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_CHALLENGE_AUTH);
  assert_int_equal (SpdmResponse->Header.Param1, 0);
  assert_int_equal (SpdmResponse->Header.Param2, 1 << 0);
  free(Data);
}

/**
  Test 4: receiving a correct RESPOND_IF_READY from the requester, after a 
  GET_MEASUREMENTS could not be processed.
  Expected behavior: the responder accepts the request and produces a valid MEASUREMENTS
  response message.
**/
void TestSpdmResponderRespondIfReadyCase4(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_MEASUREMENTS_RESPONSE *SpdmResponse; //response to the original request (MEASUREMENTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x4;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_MEASUREMENTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  SpdmContext->LocalContext.OpaqueMeasurementRspSize = 0;
  SpdmContext->LocalContext.OpaqueMeasurementRsp = NULL;

  SpdmContext->LastSpdmRequestSize = mSpdmGetMeasurementsRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetMeasurementsRequest, mSpdmGetMeasurementsRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_MEASUREMENTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check MEASUREMENT response
  ResponseSize = sizeof(Response);
  SpdmGetRandomNumber (SPDM_NONCE_SIZE, mSpdmGetMeasurementsRequest.Nonce);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest4Size, &mSpdmRespondIfReadyRequest4, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_MEASUREMENTS_RESPONSE) + sizeof(UINT16));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_MEASUREMENTS);
  assert_int_equal (SpdmResponse->Header.Param1, MEASUREMENT_BLOCK_NUMBER);
}

/**
  Test 5: receiving a correct RESPOND_IF_READY from the requester, after a 
  KEY_EXCHANGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid KEY_EXCHANGE_RSP
  response message.
**/
void TestSpdmResponderRespondIfReadyCase5(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_KEY_EXCHANGE_RESPONSE *SpdmResponse; //response to the original request (KEY_EXCHANGE_RSP)
  VOID                 *Data;
  UINTN                DataSize;
  UINT8                *Ptr;
  UINTN                DheKeySize;
  VOID                 *DHEContext;
  UINTN                OpaqueKeyExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x5;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (KEY_EXCHANGE)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  mSpdmKeyExchangeRequest.ReqSessionID = 0xFFFF;
  mSpdmKeyExchangeRequest.Reserved = 0;
  Ptr = mSpdmKeyExchangeRequest.RandomData;
  SpdmGetRandomNumber (SPDM_RANDOM_DATA_SIZE, Ptr);
  Ptr += SPDM_RANDOM_DATA_SIZE;
  DheKeySize = GetSpdmDhePubKeySize (mUseDheAlgo);
  DHEContext = SpdmDheNew (mUseDheAlgo);
  SpdmDheGenerateKey (mUseDheAlgo, DHEContext, Ptr, &DheKeySize);
  Ptr += DheKeySize;
  SpdmDheFree (mUseDheAlgo, DHEContext);
  OpaqueKeyExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  *(UINT16 *)Ptr = (UINT16)OpaqueKeyExchangeReqSize;
  Ptr += sizeof(UINT16);
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaqueKeyExchangeReqSize, Ptr);
  Ptr += OpaqueKeyExchangeReqSize;

  SpdmContext->LastSpdmRequestSize = mSpdmKeyExchangeRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmKeyExchangeRequest, mSpdmKeyExchangeRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_KEY_EXCHANGE;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check KEY_EXCHANGE_RSP response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest5Size, &mSpdmRespondIfReadyRequest5, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_KEY_EXCHANGE_RESPONSE) + DheKeySize + 2 + SpdmGetOpaqueDataVersionSelectionDataSize(SpdmContext) + GetSpdmAsymSignatureSize (mUseAsymAlgo) + GetSpdmHashSize (mUseHashAlgo));
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_KEY_EXCHANGE_RSP);
  assert_int_equal (SpdmResponse->RspSessionID, 0xFFFF);
  free(Data);
  SpdmFreeSessionId (SpdmContext, (0xFFFFFFFF));
}

/**
  Test 6: receiving a correct RESPOND_IF_READY from the requester, after a 
  FINISH could not be processed.
  Expected behavior: the responder accepts the request and produces a valid FINISH_RSP
  response message.
**/
void TestSpdmResponderRespondIfReadyCase6(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_FINISH_RESPONSE *SpdmResponse; //response to the original request (FINISH_RSP)
  VOID                 *Data;
  UINTN                DataSize;
  UINT8                *Ptr;
  UINT8                mDummyBuffer[MAX_HASH_SIZE];
  UINT8                *CertBuffer;
  UINTN                CertBufferSize;
  UINT8                CertBufferHash[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x6;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (FINISH)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.MutAuthRequested = 0;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmFinishRequest.Signature;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  CertBuffer = (UINT8 *)Data + sizeof(SPDM_CERT_CHAIN) + HashSize;
  CertBufferSize = DataSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
  SpdmHashAll (mUseHashAlgo, CertBuffer, CertBufferSize, CertBufferHash);
  // Transcript.MessageA size is 0
  AppendManagedBuffer (&THCurr, CertBufferHash, HashSize);
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmFinishRequest, sizeof(SPDM_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);

  SpdmContext->LastSpdmRequestSize = sizeof(SPDM_FINISH_REQUEST) + HmacSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmFinishRequest, mSpdmFinishRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_FINISH;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check FINISH_RSP response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest6Size, &mSpdmRespondIfReadyRequest6, &ResponseSize, Response);
  // Status = SpdmGetResponseFinish (SpdmContext, mSpdmFinishRequest1Size, &mSpdmFinishRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_FINISH_RESPONSE) + HmacSize);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_FINISH_RSP);
  free(Data);
  SpdmFreeSessionId (SpdmContext, (0xFFFFFFFF));
}

/**
  Test 7: receiving a correct RESPOND_IF_READY from the requester, after a 
  PSK_EXCHANGE could not be processed.
  Expected behavior: the responder accepts the request and produces a valid PSK_EXCHANGE_RSP
  response message.
**/
void TestSpdmResponderRespondIfReadyCase7(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_EXCHANGE_RESPONSE *SpdmResponse; //response to the original request (PSK_EXCHANGE_RSP)
  VOID                 *Data;
  UINTN                DataSize;
  UINT8                *Ptr;
  STATIC UINT8         LocalPskHint[32];
  UINTN                OpaquePskExchangeReqSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x7;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (PSK_EXCHANGE)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Algorithm.KeySchedule = mUseKeyScheduleAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  mSpdmPskExchangeRequest.PSKHintLength = (UINT16)SpdmContext->LocalContext.PskHintSize;
  mSpdmPskExchangeRequest.RequesterContextLength = DEFAULT_CONTEXT_LENGTH;
  OpaquePskExchangeReqSize = SpdmGetOpaqueDataSupportedVersionDataSize (SpdmContext);
  mSpdmPskExchangeRequest.OpaqueLength = (UINT16)OpaquePskExchangeReqSize;
  mSpdmPskExchangeRequest.ReqSessionID = 0xFFFF;
  Ptr = mSpdmPskExchangeRequest.PSKHint;
  CopyMem (Ptr, SpdmContext->LocalContext.PskHint, SpdmContext->LocalContext.PskHintSize);
  Ptr += mSpdmPskExchangeRequest.PSKHintLength;
  SpdmGetRandomNumber (DEFAULT_CONTEXT_LENGTH, Ptr);
  Ptr += mSpdmPskExchangeRequest.RequesterContextLength;
  SpdmBuildOpaqueDataSupportedVersionData (SpdmContext, &OpaquePskExchangeReqSize, Ptr);
  Ptr += OpaquePskExchangeReqSize;

  SpdmContext->LastSpdmRequestSize = mSpdmPskExchangeRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmPskExchangeRequest, mSpdmPskExchangeRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_PSK_EXCHANGE;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check PSK_EXCHANGE_RSP response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest7Size, &mSpdmRespondIfReadyRequest7, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_PSK_EXCHANGE_RESPONSE) + DEFAULT_CONTEXT_LENGTH + SpdmGetOpaqueDataVersionSelectionDataSize(SpdmContext) + GetSpdmHashSize (mUseHashAlgo));
  assert_int_equal (SpdmSecuredMessageGetSessionState (SpdmContext->SessionInfo[0].SecuredMessageContext), SpdmSessionStateHandshaking);
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_PSK_EXCHANGE_RSP);
  assert_int_equal (SpdmResponse->RspSessionID, 0xFFFF);
  free(Data);
  SpdmFreeSessionId (SpdmContext, (0xFFFFFFFF));
}

/**
  Test 8: receiving a correct RESPOND_IF_READY from the requester, after a 
  PSK_FINISH could not be processed.
  Expected behavior: the responder accepts the request and produces a valid PSK_FINISH_RSP
  response message.
**/
void TestSpdmResponderRespondIfReadyCase8(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_PSK_FINISH_RESPONSE *SpdmResponse; //response to the original request (FINISH_PSK_RSP)
  VOID                 *Data;
  UINTN                DataSize;
  UINT8                *Ptr;
  UINT8                LocalPskHint[32];
  UINT8                mDummyBuffer[MAX_HASH_SIZE];
  LARGE_MANAGED_BUFFER THCurr;
  UINT8                RequestFinishedKey[MAX_HASH_SIZE];
  SPDM_SESSION_INFO    *SessionInfo;
  UINT32               SessionId;
  UINT32               HashSize;
  UINT32               HmacSize;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x8;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (FINISH)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateAuthenticated;
  SpdmContext->LocalContext.Capability.Flags = 0;
  SpdmContext->ConnectionInfo.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP;
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = mUseAsymAlgo;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementSpec = mUseMeasurementSpec;
  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = mUseMeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = mUseDheAlgo;
  SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = mUseAeadAlgo;
  SpdmContext->ConnectionInfo.Version.SpdmVersionCount = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MajorVersion = 1;
  SpdmContext->ConnectionInfo.Version.SpdmVersion[0].MinorVersion = 1;
  ReadResponderPublicCertificateChain (mUseHashAlgo, mUseAsymAlgo, &Data, &DataSize, NULL, NULL);
  SpdmContext->LocalContext.LocalCertChainProvision[0] = Data;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = DataSize;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = Data;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBufferSize = DataSize;
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LocalContext.MutAuthRequested = 0;
  ZeroMem (LocalPskHint, 32);
  CopyMem (&LocalPskHint[0], TEST_PSK_HINT_STRING, sizeof(TEST_PSK_HINT_STRING));
  SpdmContext->LocalContext.PskHintSize = sizeof(TEST_PSK_HINT_STRING);
  SpdmContext->LocalContext.PskHint = LocalPskHint;

  SessionId = 0xFFFFFFFF;
  SpdmContext->LatestSessionId = SessionId;
  SpdmContext->LastSpdmRequestSessionIdValid = TRUE;
  SpdmContext->LastSpdmRequestSessionId = SessionId;
  SessionInfo = &SpdmContext->SessionInfo[0];
  SpdmSessionInfoInit (SpdmContext, SessionInfo, SessionId, FALSE);
  HashSize = GetSpdmHashSize (mUseHashAlgo);
  SetMem (mDummyBuffer, HashSize, (UINT8)(0xFF));
  SpdmSecuredMessageSetRequestFinishedKey (SessionInfo->SecuredMessageContext, mDummyBuffer, HashSize);
  SpdmSecuredMessageSetSessionState (SessionInfo->SecuredMessageContext, SpdmSessionStateHandshaking);

  HashSize = GetSpdmHashSize (mUseHashAlgo);
  HmacSize = GetSpdmHashSize (mUseHashAlgo);
  Ptr = mSpdmPskFinishRequest.VerifyData;
  InitManagedBuffer (&THCurr, MAX_SPDM_MESSAGE_BUFFER_SIZE);
  // Transcript.MessageA size is 0
  // SessionTranscript.MessageK is 0 
  AppendManagedBuffer (&THCurr, (UINT8 *)&mSpdmPskFinishRequest, sizeof(SPDM_PSK_FINISH_REQUEST));
  SetMem (RequestFinishedKey, MAX_HASH_SIZE, (UINT8)(0xFF));
  SpdmHmacAll (mUseHashAlgo, GetManagedBuffer(&THCurr), GetManagedBufferSize(&THCurr), RequestFinishedKey, HashSize, Ptr);

  SpdmContext->LastSpdmRequestSize = sizeof(SPDM_PSK_FINISH_REQUEST) + HmacSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmPskFinishRequest, mSpdmPskFinishRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_PSK_FINISH;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check FINISH_PSK_RSP response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest8Size, &mSpdmRespondIfReadyRequest8, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_PSK_FINISH_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_PSK_FINISH_RSP);
  free(Data);
  SpdmFreeSessionId (SpdmContext, (0xFFFFFFFF));
}

/**
  Test 9: receiving a RESPOND_IF_READY message larger than specified (more parameters 
  than the header), after a GET_DIGESTS could not be processed.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderRespondIfReadyCase9(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0x9;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest9Size, &mSpdmRespondIfReadyRequest9, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

/**
  Test 10: receiving a correct RESPOND_IF_READY from the requester, but the responder is in
  a Busy state.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the Busy state.
**/
void TestSpdmResponderRespondIfReadyCase10(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xA;
  SpdmContext->ResponseState = SpdmResponseStateBusy;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest1Size, &mSpdmRespondIfReadyRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_BUSY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateBusy);
}

/**
  Test 11: receiving a correct RESPOND_IF_READY from the requester, but the responder requires
  resynchronization with the requester.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the NeedResynch state.
**/
void TestSpdmResponderRespondIfReadyCase11(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xB;
  SpdmContext->ResponseState = SpdmResponseStateNeedResync;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest1Size, &mSpdmRespondIfReadyRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_REQUEST_RESYNCH);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNeedResync);
}

/**
  Test 12: receiving a correct RESPOND_IF_READY from the requester, but the responder could not
  produce the response in time.
  Expected behavior: the responder accepts the request, but produces an ERROR message
  indicating the ResponseNotReady state, with the same token as the request.
**/
void TestSpdmResponderRespondIfReadyCase12(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)
  SPDM_ERROR_DATA_RESPONSE_NOT_READY *ErrorData;

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xC;
  SpdmContext->ResponseState = SpdmResponseStateNotReady;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest1Size, &mSpdmRespondIfReadyRequest1, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE) + sizeof(SPDM_ERROR_DATA_RESPONSE_NOT_READY));
  SpdmResponse = (VOID *)Response;
  ErrorData = (SPDM_ERROR_DATA_RESPONSE_NOT_READY*)(SpdmResponse + 1);
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_RESPONSE_NOT_READY);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
  assert_int_equal (SpdmContext->ResponseState, SpdmResponseStateNotReady);
  assert_int_equal (ErrorData->RequestCode, SPDM_GET_DIGESTS);
  assert_int_equal (ErrorData->Token, MyTestToken);
}

/**
  Test 13: receiving a correct RESPOND_IF_READY from the requester, with the correct original
  request code, but with a token different from the expected.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderRespondIfReadyCase13(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xD;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest10Size, &mSpdmRespondIfReadyRequest10, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

/**
  Test 14: receiving a correct RESPOND_IF_READY from the requester, with the correct token, 
  but with a request code different from the expected.
  Expected behavior: the responder refuses the RESPOND_IF_READY message and produces an
  ERROR message indicating the InvalidRequest.
**/
void TestSpdmResponderRespondIfReadyCase14(void **state) {
  RETURN_STATUS        Status;
  SPDM_TEST_CONTEXT    *SpdmTestContext;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                ResponseSize;
  UINT8                Response[MAX_SPDM_MESSAGE_BUFFER_SIZE];
  SPDM_DIGESTS_RESPONSE *SpdmResponse; //response to the original request (DIGESTS)

  SpdmTestContext = *state;
  SpdmContext = SpdmTestContext->SpdmContext;
  SpdmTestContext->CaseId = 0xE;
  SpdmContext->ResponseState = SpdmResponseStateNormal;

  //state for the the original request (GET_DIGESTS)
  SpdmContext->ConnectionInfo.ConnectionState = SpdmConnectionStateNegotiated; 
  SpdmContext->LocalContext.Capability.Flags |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = mUseHashAlgo;
  SpdmContext->LocalContext.LocalCertChainProvision[0] = LocalCertificateChain;
  SpdmContext->LocalContext.LocalCertChainProvisionSize[0] = MAX_SPDM_MESSAGE_BUFFER_SIZE;
  SetMem (LocalCertificateChain, MAX_SPDM_MESSAGE_BUFFER_SIZE, (UINT8)(0xFF));
  SpdmContext->LocalContext.SlotCount = 1;
  SpdmContext->LastSpdmRequestSize = mSpdmGetDigestRequestSize;
  CopyMem (SpdmContext->LastSpdmRequest, &mSpdmGetDigestRequest, mSpdmGetDigestRequestSize);

  //RESPOND_IF_READY specific data
  SpdmContext->CachSpdmRequestSize = SpdmContext->LastSpdmRequestSize;
  CopyMem (SpdmContext->CachSpdmRequest, SpdmContext->LastSpdmRequest, SpdmContext->LastSpdmRequestSize);
  SpdmContext->ErrorData.RDTExponent = 1;
  SpdmContext->ErrorData.RDTM        = 1;
  SpdmContext->ErrorData.RequestCode = SPDM_GET_DIGESTS;
  SpdmContext->ErrorData.Token       = MyTestToken;

  //check ERROR response
  ResponseSize = sizeof(Response);
  Status = SpdmGetResponseRespondIfReady(SpdmContext, mSpdmRespondIfReadyRequest11Size, &mSpdmRespondIfReadyRequest11, &ResponseSize, Response);
  assert_int_equal (Status, RETURN_SUCCESS);
  assert_int_equal (ResponseSize, sizeof(SPDM_ERROR_RESPONSE));
  SpdmResponse = (VOID *)Response;
  assert_int_equal (SpdmResponse->Header.RequestResponseCode, SPDM_ERROR);
  assert_int_equal (SpdmResponse->Header.Param1, SPDM_ERROR_CODE_INVALID_REQUEST);
  assert_int_equal (SpdmResponse->Header.Param2, 0);
}

SPDM_TEST_CONTEXT       mSpdmResponderRespondIfReadyTestContext = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

int SpdmResponderRespondIfReadyTestMain(void) {
  const struct CMUnitTest SpdmResponderRespondIfReadyTests[] = {
    // Success Case
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase1),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase2),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase3),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase4),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase5),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase6),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase7),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase8),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase9),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase10),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase11),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase12),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase13),
    cmocka_unit_test(TestSpdmResponderRespondIfReadyCase14),
  };

  SetupSpdmTestContext (&mSpdmResponderRespondIfReadyTestContext);

  return cmocka_run_group_tests(SpdmResponderRespondIfReadyTests, SpdmUnitTestGroupSetup, SpdmUnitTestGroupTeardown);
}
