/** @file
  Definitions of Security Protocol & Data Model Specification (SPDM)
  version 1.1.0 in Distributed Management Task Force (DMTF).

Copyright (c) 2019 - 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#ifndef __SPDM_H__
#define __SPDM_H__

#pragma pack(1)

///
/// SPDM response code
///
#define SPDM_DIGESTS                        0x01
#define SPDM_CERTIFICATE                    0x02
#define SPDM_CHALLENGE_AUTH                 0x03
#define SPDM_VERSION                        0x04
#define SPDM_MEASUREMENTS                   0x60
#define SPDM_CAPABILITIES                   0x61
#define SPDM_ALGORITHMS                     0x63
#define SPDM_KEY_EXCHANGE_RSP               0x64
#define SPDM_FINISH_RSP                     0x65
#define SPDM_PSK_EXCHANGE_RSP               0x66
#define SPDM_PSK_FINISH_RSP                 0x67
#define SPDM_HEARTBEAT_ACK                  0x68
#define SPDM_KEY_UPDATE_ACK                 0x69
#define SPDM_ENCAPSULATED_REQUEST           0x6A
#define SPDM_ENCAPSULATED_RESPONSE_ACK      0x6B
#define SPDM_END_SESSION_ACK                0x6C
#define SPDM_VENDOR_DEFINED_RESPONSE        0x7E
#define SPDM_ERROR                          0x7F
///
/// SPDM request code
///
#define SPDM_GET_DIGESTS                    0x81
#define SPDM_GET_CERTIFICATE                0x82
#define SPDM_CHALLENGE                      0x83
#define SPDM_GET_VERSION                    0x84
#define SPDM_GET_MEASUREMENTS               0xE0
#define SPDM_GET_CAPABILITIES               0xE1
#define SPDM_NEGOTIATE_ALGORITHMS           0xE3
#define SPDM_KEY_EXCHANGE                   0xE4
#define SPDM_FINISH                         0xE5
#define SPDM_PSK_EXCHANGE                   0xE6
#define SPDM_PSK_FINISH                     0xE7
#define SPDM_HEARTBEAT                      0xE8
#define SPDM_KEY_UPDATE                     0xE9
#define SPDM_GET_ENCAPSULATED_REQUEST       0xEA
#define SPDM_DELIVER_ENCAPSULATED_RESPONSE  0xEB
#define SPDM_END_SESSION                    0xEC
#define SPDM_VENDOR_DEFINED_REQUEST         0xFE
#define SPDM_RESPOND_IF_READY               0xFF

///
/// SPDM message header
///
typedef struct {
  UINT8   SPDMVersion;
  UINT8   RequestResponseCode;
  UINT8   Param1;
  UINT8   Param2;
} SPDM_MESSAGE_HEADER;

#define SPDM_MESSAGE_VERSION_10  0x10
#define SPDM_MESSAGE_VERSION_11  0x11
#define SPDM_MESSAGE_VERSION     SPDM_MESSAGE_VERSION_10

///
/// SPDM GET_VERSION request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_GET_VERSION_REQUEST;

///
/// SPDM GET_VERSION response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT8                Reserved;
  UINT8                VersionNumberEntryCount;
//SPDM_VERSION_NUMBER  VersionNumberEntry[VersionNumberEntryCount];
} SPDM_VERSION_RESPONSE;

///
/// SPDM VERSION structure
///
typedef struct {
  UINT16               Alpha:4;
  UINT16               UpdateVersionNumber:4;
  UINT16               MinorVersion:4;
  UINT16               MajorVersion:4;
} SPDM_VERSION_NUMBER;

///
/// SPDM GET_CAPABILITIES request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT8                Reserved;
  UINT8                CTExponent;
  UINT16               Reserved2;
  UINT32               Flags;
} SPDM_GET_CAPABILITIES_REQUEST;

///
/// SPDM GET_CAPABILITIES response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT8                Reserved;
  UINT8                CTExponent;
  UINT16               Reserved2;
  UINT32               Flags;
} SPDM_CAPABILITIES_RESPONSE;

///
/// SPDM GET_CAPABILITIES response Flags
///
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP                       BIT0 // responder only
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP                        BIT1
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP                        BIT2
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP                        (BIT3 | BIT4)
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG                   BIT3
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG                      BIT4
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP                  BIT5
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP                     BIT6
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP                         BIT7
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP                    BIT8
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP                      BIT9
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP                         (BIT10 | BIT11)
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_REQUESTER                 BIT10
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER                 BIT10
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT    BIT11
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP                       BIT12
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP                       BIT13
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP                     BIT14
#define SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP      BIT15

///
/// SPDM NEGOTIATE_ALGORITHMS request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == Number of Algorithms Structure Tables 
  // Param2 == RSVD
  UINT16               Length;
  UINT8                MeasurementSpecification;
  UINT8                Reserved;
  UINT32               BaseAsymAlgo;
  UINT32               BaseHashAlgo;
  UINT8                Reserved2[12];
  UINT8                ExtAsymCount;
  UINT8                ExtHashCount;
  UINT16               Reserved3;
//UINT32               ExtAsym[ExtAsymCount];
//UINT32               ExtHash[ExtHashCount];
//SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE  AlgStruct[Param1];
} SPDM_NEGOTIATE_ALGORITHMS_REQUEST;

typedef struct {
  UINT8                AlgType;
  UINT8                AlgCount; // BIT[0:3]=ExtAlgCount, BIT[4:7]=FixedAlgByteCount
//UINT8                AlgSupported[FixedAlgByteCount];
//UINT32               AlgExternal[ExtAlgCount];
} SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE;

#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE                0
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD               1
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG  2
#define SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE       3

typedef struct {
  UINT8                AlgType;
  UINT8                AlgCount;
  UINT16               AlgSupported;
} SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE;

///
/// SPDM NEGOTIATE_ALGORITHMS request BaseAsymAlgo/REQ_BASE_ASYM_ALG
///
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048           BIT0
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048           BIT1
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072           BIT2
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072           BIT3
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256   BIT4
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096           BIT5
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096           BIT6
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384   BIT7
#define SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521   BIT8

///
/// SPDM NEGOTIATE_ALGORITHMS request BaseHashAlgo
///
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256               BIT0
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384               BIT1
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512               BIT2
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256              BIT3
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384              BIT4
#define SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512              BIT5

///
/// SPDM NEGOTIATE_ALGORITHMS request DHE
///
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048                   BIT0
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072                   BIT1
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096                   BIT2
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1                  BIT3
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1                  BIT4
#define SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1                  BIT5

///
/// SPDM NEGOTIATE_ALGORITHMS request AEAD
///
#define SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM                BIT0
#define SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM                BIT1
#define SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305          BIT2

///
/// SPDM NEGOTIATE_ALGORITHMS request KEY_SCHEDULE
///
#define SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH                       BIT0

///
/// SPDM NEGOTIATE_ALGORITHMS response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == Number of Algorithms Structure Tables
  // Param2 == RSVD
  UINT16               Length;
  UINT8                MeasurementSpecificationSel;
  UINT8                Reserved;
  UINT32               MeasurementHashAlgo;
  UINT32               BaseAsymSel;
  UINT32               BaseHashSel;
  UINT8                Reserved2[12];
  UINT8                ExtAsymSelCount;
  UINT8                ExtHashSelCount;
  UINT16               Reserved3;
//UINT32               ExtAsymSel[ExtAsymSelCount];
//UINT32               ExtHashSel[ExtHashSelCount];
//SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE  AlgStruct[Param1];
} SPDM_ALGORITHMS_RESPONSE;

///
/// SPDM NEGOTIATE_ALGORITHMS response MeasurementHashAlgo
///
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY BIT0
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256     BIT1
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384     BIT2
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512     BIT3
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256    BIT4
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384    BIT5
#define SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512    BIT6

///
/// SPDM extended algorithm
///
typedef struct {
  UINT8                RegistryID;
  UINT8                Reserved;
  UINT16               AlgorithmID;
} SPDM_EXTENDED_ALGORITHM;

///
/// SPDM extended algorithm RegistryID
///
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_DMTF      0
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_TCG       1
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_USB       2
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_PCISIG    3
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_IANA      4
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_HDBASET   5
#define SPDM_EXTENDED_ALGORITHM_REGISTRY_ID_MIPI      6

///
/// SPDM GET_DIGESTS request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_GET_DIGESTS_REQUEST;

///
/// SPDM GET_DIGESTS response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == SlotMask
//UINT8                Digest[DigestSize][SlotCount];
} SPDM_DIGESTS_RESPONSE;

///
/// SPDM GET_DIGESTS request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == SlotNum
  // Param2 == RSVD
  UINT16               Offset;
  UINT16               Length;
} SPDM_GET_CERTIFICATE_REQUEST;

///
/// SPDM GET_DIGESTS response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == SlotNum
  // Param2 == RSVD
  UINT16               PortionLength;
  UINT16               RemainderLength;
//UINT8                CertChain[PortionLength];
} SPDM_CERTIFICATE_RESPONSE;

typedef struct {
  //
  // Total length of the certificate chain, in bytes,
  // including all fields in this table.
  //
  UINT16   Length;
  UINT16   Reserved;
  //
  // Digest of the Root Certificate.
  // Note that Root Certificate is ASN.1 DER-encoded for this digest.
  // The hash size is determined by the SPDM device.
  //
//UINT8    RootHash[HashSize];
  //
  // One or more ASN.1 DER-encoded X509v3 certificates where the first certificate is signed by the Root
  // Certificate or is the Root Certificate itself and each subsequent certificate is signed by the preceding
  // certificate. The last certificate is the Leaf Certificate.
  //
//UINT8    Certificates[Length - 4 - HashSize];
} SPDM_CERT_CHAIN;

///
/// SPDM CHALLENGE request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == SlotNum
  // Param2 == HashType
  UINT8                Nonce[32];
} SPDM_CHALLENGE_REQUEST;

///
/// SPDM CHALLENGE request HashType
///
#define SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH      0
#define SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH   1
#define SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH            0xFF

///
/// SPDM CHALLENGE response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == SlotNum
  // Param2 == SlotMask
//UINT8                CertChainHash[DigestSize];
//UINT8                Nonce[32];
//UINT8                MeasurementSummaryHash[DigestSize];
//UINT16               OpaqueLength;
//UINT8                OpaqueData[OpaqueLength];
//UINT8                Signature[KeySize];
} SPDM_CHALLENGE_AUTH_RESPONSE;

///
/// SPDM GET_MEASUREMENTS request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == Attributes
  // Param2 == MeasurementOperation
  UINT8                Nonce[32];
} SPDM_GET_MEASUREMENTS_REQUEST;

///
/// SPDM GET_MEASUREMENTS request Attributes
///
#define SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE     BIT0

///
/// SPDM GET_MEASUREMENTS request MeasurementOperation
///
#define SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS  0
//SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_INDEX
#define SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS               0xFF

///
/// SPDM MEASUREMENTS block common header
///
typedef struct {
  UINT8                Index;
  UINT8                MeasurementSpecification;
  UINT16               MeasurementSize;
//UINT8                Measurement[MeasurementSize];
} SPDM_MEASUREMENT_BLOCK_COMMON_HEADER;

#define SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF BIT0

///
/// SPDM MEASUREMENTS block DMTF header
///
typedef struct {
  UINT8                DMTFSpecMeasurementValueType;
  UINT16               DMTFSpecMeasurementValueSize;
//UINT8                DMTFSpecMeasurementValue[DMTFSpecMeasurementValueSize];
} SPDM_MEASUREMENT_BLOCK_DMTF_HEADER;

typedef struct {
  SPDM_MEASUREMENT_BLOCK_COMMON_HEADER  MeasurementBlockCommonHeader;
  SPDM_MEASUREMENT_BLOCK_DMTF_HEADER    MeasurementBlockDmtfHeader;
//UINT8                                 HashValue[HashSize];
} SPDM_MEASUREMENT_BLOCK_DMTF;

///
/// SPDM MEASUREMENTS block MeasurementValueType
///
#define SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM           0
#define SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE        1
#define SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HARDWARE_CONFIGURATION  2
#define SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_FIRMWARE_CONFIGURATION  3
#define SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM          BIT7

///
/// SPDM GET_MEASUREMENTS response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == TotalNumberOfMeasurement/RSVD
  // Param2 == RSVD
  UINT8                NumberOfBlocks;
  UINT8                MeasurementRecordLength[3];
//UINT8                MeasurementRecord[MeasurementRecordLength];
//UINT8                Nonce[32];
//UINT16               OpaqueLength;
//UINT8                OpaqueData[OpaqueLength];
//UINT8                Signature[KeySize];
} SPDM_MEASUREMENTS_RESPONSE;

///
/// SPDM ERROR response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == Error Code
  // Param2 == Error Data
//UINT8                ExtendedErrorData[];
} SPDM_ERROR_RESPONSE;

///
/// SPDM error code
///
#define SPDM_ERROR_CODE_INVALID_REQUEST         0x01
#define SPDM_ERROR_CODE_BUSY                    0x03
#define SPDM_ERROR_CODE_UNEXPECTED_REQUEST      0x04
#define SPDM_ERROR_CODE_UNSPECIFIED             0x05
#define SPDM_ERROR_CODE_UNSUPPORTED_REQUEST     0x07
#define SPDM_ERROR_CODE_MAJOR_VERSION_MISMATCH  0x41
#define SPDM_ERROR_CODE_RESPONSE_NOT_READY      0x42
#define SPDM_ERROR_CODE_REQUEST_RESYNCH         0x43

///
/// SPDM RESPONSE_IF_READY request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RequestCode
  // Param2 == Token
} SPDM_RESPONSE_IF_READY_REQUEST;

///
/// SPDM VENDOR_DEFINED request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT16               StandardID;
  UINT8                Len;
//UINT8                VendorID[Len];
//UINT16               PayloadLength;
//UINT8                VendorDefinedPayload[PayloadLength];
} SPDM_VENDOR_DEFINED_REQUEST_MSG;

///
/// SPDM VENDOR_DEFINED response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
  UINT16               StandardID;
  UINT8                Len;
//UINT8                VendorID[Len];
//UINT16               PayloadLength;
//UINT8                VendorDefinedPayload[PayloadLength];
} SPDM_VENDOR_DEFINED_RESPONSE_MSG;

///
/// SPDM KEY_EXCHANGE request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == HashType
  // Param2 == SlotNum
  UINT32               DHE_Named_Group;
  UINT8                RandomData[32];
//UINT8                ExchangeData[D];
//UINT16               OpaqueLength;
//UINT8                OpaqueData[OpaqueLength];
} SPDM_KEY_EXCHANGE_REQUEST;

///
/// SPDM KEY_EXCHANGE request HashType
///
#define SPDM_KEY_EXCHANGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH      0
#define SPDM_KEY_EXCHANGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH   1
#define SPDM_KEY_EXCHANGE_REQUEST_ALL_MEASUREMENTS_HASH            0xFF

///
/// SPDM KEY_EXCHANGE request DHE_Named_Group
///
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE2048 BIT0
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE3072 BIT1
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_FFDHE4096 BIT2
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP256R1 BIT3
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP384R1 BIT4
#define SPDM_KEY_EXCHANGE_REQUEST_DHE_NAME_GROUP_SECP521R1 BIT5

///
/// SPDM KEY_EXCHANGE response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == HeartbeatPeriod
  // Param2 == SessionID
  UINT16               Length;
  UINT8                Mut_Auth_Requested;
  UINT8                Reserved;
  UINT8                RandomData[32];
//UINT8                ExchangeData[D];
//UINT8                MeasurementSummaryHash[DigestSize];
//UINT8                Signature[S];
//UINT8                VerifyData[O];
} SPDM_KEY_EXCHANGE_RESPONSE;

///
/// SPDM KEY_EXCHANGE response Mut_Auth_Requested
///
#define SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED                   BIT0
#define SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS  BIT1

///
/// SPDM FINISH request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == SignatureIncluded
  // Param2 == SlotNum
//UINT8                Signature[S];
//UINT8                VerifyData[H];
} SPDM_FINISH_REQUEST;

///
/// SPDM FINISH request SignatureIncluded
///
#define SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED   BIT0

///
/// SPDM FINISH response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
//UINT8                VerifyData[O];
} SPDM_FINISH_RESPONSE;

///
/// SPDM PSK_EXCHANGE request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == HashType
  // Param2 == RSVD
  UINT16               OpaqueLength;
  UINT8                RequesterContextLength;
  UINT8                Reserved;
//UINT8                RequesterContext[RequesterContextLength];
//UINT8                OpaqueData[OpaqueLength];
} SPDM_PSK_EXCHANGE_REQUEST;

///
/// SPDM PSK_EXCHANGE response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == HeartbeatPeriod
  // Param2 == SessionID
  UINT8                ResponderContextLength;
  UINT8                Reserved[3];
//UINT8                ResponderContext[ResponderContextLength];
//UINT8                MeasurementSummaryHash[DigestSize];
//UINT8                VerifyData[H];
} SPDM_PSK_EXCHANGE_RESPONSE;

///
/// SPDM PSK_FINISH request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
//UINT8                RequesterVerifyData[H];
} SPDM_PSK_FINISH_REQUEST;

///
/// SPDM PSK_FINISH response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_PSK_FINISH_RESPONSE;

///
/// SPDM HEARTBEAT request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_HEARTBEAT_REQUEST;

///
/// SPDM HEARTBEAT response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_HEARTBEAT_RESPONSE;

///
/// SPDM KEY_UPDATE request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == KeyOperation
  // Param2 == Tag
} SPDM_KEY_UPDATE_REQUEST;

///
/// SPDM KEY_UPDATE Operations Table
///
#define SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY         1
#define SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS    2
#define SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY     3

///
/// SPDM KEY_UPDATE response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == KeyOperation
  // Param2 == Tag
} SPDM_KEY_UPDATE_RESPONSE;

///
/// SPDM GET_ENCAPSULATED_REQUEST request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_GET_ENCAPSULATED_REQUEST_REQUEST;

///
/// SPDM ENCAPSULATED_REQUEST response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RequestID
  // Param2 == RSVD
//UINT8                EncapsulatedRequest[];
} SPDM_ENCAPSULATED_REQUEST_RESPONSE;

///
/// SPDM DELIVER_ENCAPSULATED_RESPONSE request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RequestID
  // Param2 == RSVD
//UINT8                EncapsulatedResponse[];
} SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST;

///
/// SPDM ENCAPSULATED_RESPONSE_ACK response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RequestID
  // Param2 == RSVD
//UINT8                EncapsulatedRequest[];
} SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE;

///
/// SPDM END_SESSION request
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == EndSessionRequestAttributes
  // Param2 == RSVD
} SPDM_END_SESSION_REQUEST;

///
/// SPDM END_SESSION request Attributes
///
#define SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE BIT0

///
/// SPDM END_SESSION response
///
typedef struct {
  SPDM_MESSAGE_HEADER  Header;
  // Param1 == RSVD
  // Param2 == RSVD
} SPDM_END_SESSION_RESPONSE;

#pragma pack()

#endif

