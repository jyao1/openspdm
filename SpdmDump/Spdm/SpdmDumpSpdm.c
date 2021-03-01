/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID               *mSpdmDecMessageBuffer;
VOID               *mSpdmContext;

VOID               *mSpdmLastMessageBuffer;
UINTN              mSpdmLastMessageBufferSize;
UINT8              mCachedGetMeasurementRequestAttribute;
UINT8              mCachedGetMeasurementOperation;
UINT8              mCachedMeasurementSummaryHashType;
UINT32             mCachedSessionId;
VOID               *mCurrentSessionInfo;
UINT32             mCurrentSessionId;
BOOLEAN            mEncapsulated;
BOOLEAN            mDecrypted;

VOID               *mSpdmCertChainBuffer;
UINTN              mSpdmCertChainBufferSize;
UINTN              mCachedSpdmCertChainBufferOffset;

VOID               *mLocalUsedCertChainBuffer;
UINTN              mLocalUsedCertChainBufferSize;
VOID               *mPeerCertChainBuffer;
UINTN              mPeerCertChainBufferSize;

UINT32             mSpdmRequesterCapabilitiesFlags;
UINT32             mSpdmResponderCapabilitiesFlags;
UINT8              mSpdmMeasurementSpec;
UINT32             mSpdmMeasurementHashAlgo;
UINT32             mSpdmBaseAsymAlgo;
UINT32             mSpdmBaseHashAlgo;
UINT16             mSpdmDHENamedGroup;
UINT16             mSpdmAEADCipherSuite;
UINT16             mSpdmReqBaseAsymAlg;
UINT16             mSpdmKeySchedule;

DISPATCH_TABLE_ENTRY mSpdmVendorDispatch[] = {
  {SPDM_REGISTRY_ID_DMTF,    "DMTF",    NULL},
  {SPDM_REGISTRY_ID_TCG,     "TCG",     NULL},
  {SPDM_REGISTRY_ID_USB,     "USB",     NULL},
  {SPDM_REGISTRY_ID_PCISIG,  "PCISIG",  DumpSpdmVendorPci},
  {SPDM_REGISTRY_ID_IANA,    "IANA",    NULL},
  {SPDM_REGISTRY_ID_HDBASET, "HDBASET", NULL},
  {SPDM_REGISTRY_ID_MIPI,    "MIPI",    NULL},
  {SPDM_REGISTRY_ID_CXL,     "CXL",     NULL},
  {SPDM_REGISTRY_ID_JEDEC,   "JEDEC",   NULL},
};

VALUE_STRING_ENTRY  mSpdmRequesterCapabilitiesStringTable[] = {
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP,                   "CERT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP,                   "CHAL"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP,                "ENCRYPT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP,                    "MAC"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP,               "MUT_AUTH"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP,                 "KEY_EX"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER,          "PSK"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP,                  "ENCAP"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP,                  "HBEAT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP,                "KEY_UPD"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP, "HANDSHAKE_IN_CLEAR"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP,             "PUB_KEY_ID"},
};
UINTN mSpdmRequesterCapabilitiesStringTableCount = ARRAY_SIZE(mSpdmRequesterCapabilitiesStringTable);

VALUE_STRING_ENTRY  mSpdmResponderCapabilitiesStringTable[] = {
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP,                      "CACHE"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP,                       "CERT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP,                       "CHAL"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG,                "MEAS_NO_SIG"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG,                   "MEAS_SIG"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP,                 "MEAS_FRESH"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP,                    "ENCRYPT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP,                        "MAC"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP,                   "MUT_AUTH"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP,                     "KEY_EX"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER,              "PSK"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT, "PSK_WITH_CONTEXT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP,                      "ENCAP"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP,                      "HBEAT"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP,                    "KEY_UPD"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,     "HANDSHAKE_IN_CLEAR"},
  {SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP,                 "PUB_KEY_ID"},
};
UINTN mSpdmResponderCapabilitiesStringTableCount = ARRAY_SIZE(mSpdmResponderCapabilitiesStringTable);

VALUE_STRING_ENTRY  mSpdmHashValueStringTable[] = {
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};
UINTN mSpdmHashValueStringTableCount = ARRAY_SIZE(mSpdmHashValueStringTable);

VALUE_STRING_ENTRY  mSpdmMeasurementHashValueStringTable[] = {
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,  "RAW_BIT"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,      "SHA_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,      "SHA_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,      "SHA_512"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,     "SHA3_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,     "SHA3_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,     "SHA3_512"},
};
UINTN mSpdmMeasurementHashValueStringTableCount = ARRAY_SIZE(mSpdmMeasurementHashValueStringTable);

VALUE_STRING_ENTRY  mSpdmAsymValueStringTable[] = {
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,          "RSASSA_2048"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,          "RSASSA_3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,          "RSASSA_4096"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,          "RSAPSS_2048"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,          "RSAPSS_3072"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,          "RSAPSS_4096"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,  "ECDSA_P256"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,  "ECDSA_P384"},
  {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,  "ECDSA_P521"},
};
UINTN mSpdmAsymValueStringTableCount = ARRAY_SIZE(mSpdmAsymValueStringTable);

VALUE_STRING_ENTRY  mSpdmDheValueStringTable[] = {
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,  "FFDHE_2048"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,  "FFDHE_3072"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,  "FFDHE_4096"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1"},
};
UINTN mSpdmDheValueStringTableCount = ARRAY_SIZE(mSpdmDheValueStringTable);

VALUE_STRING_ENTRY  mSpdmAeadValueStringTable[] = {
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,        "AES_128_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,        "AES_256_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,  "CHACHA20_POLY1305"},
};
UINTN mSpdmAeadValueStringTableCount = ARRAY_SIZE(mSpdmAeadValueStringTable);

VALUE_STRING_ENTRY  mSpdmKeyScheduleValueStringTable[] = {
  {SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,        "HMAC_HASH"},
};
UINTN mSpdmKeyScheduleValueStringTableCount = ARRAY_SIZE(mSpdmKeyScheduleValueStringTable);

VALUE_STRING_ENTRY  mSpdmMeasurementSpecValueStringTable[] = {
  {SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,        "DMTF"},
};
UINTN mSpdmMeasurementSpecValueStringTableCount = ARRAY_SIZE(mSpdmMeasurementSpecValueStringTable);

VALUE_STRING_ENTRY  mSpdmMeasurementTypeValueStringTable[] = {
  {SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM,          "ImmutableROM"},
  {SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE,       "MutableFirmware"},
  {SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HARDWARE_CONFIGURATION, "HardwareConfig"},
  {SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_FIRMWARE_CONFIGURATION, "FirmwareConfig"},
  {SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST,   "Manifest"},
};

VALUE_STRING_ENTRY  mSpdmRequestHashTypeStringTable[] = {
  {SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,    "NoHash"},
  {SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, "TcbHash"},
  {SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,          "AllHash"},
};

VALUE_STRING_ENTRY  mSpdmMeasurementAttributeStringTable[] = {
  {SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE, "GenSig"},
};

VALUE_STRING_ENTRY  mSpdmChallengeAuthAttributeStringTable[] = {
  {SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ, "BasicMutAuth"},
};

VALUE_STRING_ENTRY  mSpdmKeyExchangeMutAuthStringTable[] = {
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED,                    "MutAuthNoEncap"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST, "MutAuthWithEncap"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,   "MutAuthWithGetDigests"},
};

VALUE_STRING_ENTRY  mSpdmKeyUpdateOperationStringTable[] = {
  {SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY,      "UpdateKey"},
  {SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS, "UpdateAllkeys"},
  {SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY,  "VerifyNewKey"},
};

VALUE_STRING_ENTRY  mSpdmEndSessionAttributeStringTable[] = {
  {SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR, "PreserveStateClear"},
};

UINT32
SpdmDumpGetMeasurementSummaryHashSize (
  IN     UINT8                MeasurementSummaryHashType
  )
{
  // Requester does not support measurement
  if (mEncapsulated) {
    return 0;
  }
  // Check responder capabilities
  if ((mSpdmResponderCapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) {
    return 0;
  }

  switch (MeasurementSummaryHashType) {
  case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
    return 0;
    break;

  case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
  case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
    return GetSpdmHashSize (mSpdmBaseHashAlgo);
    break;
  }

  return 0;
}

VOID
DumpSpdmGetVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                MessageSize;

  printf ("SPDM_GET_VERSION ");

  MessageSize = sizeof(SPDM_GET_VERSION_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");

  SpdmResetMessageA (mSpdmContext);
  SpdmResetMessageB (mSpdmContext);
  SpdmResetMessageC (mSpdmContext);
  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                  MessageSize;
  SPDM_VERSION_RESPONSE  *SpdmResponse;
  SPDM_VERSION_NUMBER    *SpdmVersionNumber;
  UINTN                  Index;

  printf ("SPDM_VERSION ");

  MessageSize = sizeof(SPDM_VERSION_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  MessageSize += SpdmResponse->VersionNumberEntryCount * sizeof(SPDM_VERSION_NUMBER);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    SpdmVersionNumber = (VOID *)((UINTN)Buffer + sizeof(SPDM_VERSION_RESPONSE));
    printf ("(");
    for (Index = 0; Index < SpdmResponse->VersionNumberEntryCount; Index ++) {
      if (Index != 0) {
        printf (", ");
      }
      printf ("%d.%d.%d.%d",
        SpdmVersionNumber[Index].MajorVersion,
        SpdmVersionNumber[Index].MinorVersion,
        SpdmVersionNumber[Index].UpdateVersionNumber,
        SpdmVersionNumber[Index].Alpha
        );
    }
    printf (") ");
  }
  printf ("\n");

  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmGetCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                          MessageSize;
  SPDM_GET_CAPABILITIES_REQUEST  *SpdmRequest;
  SPDM_DATA_PARAMETER            Parameter;

  printf ("SPDM_GET_CAPABILITIES ");

  MessageSize = OFFSET_OF(SPDM_GET_CAPABILITIES_REQUEST, Reserved);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    MessageSize = sizeof(SPDM_GET_CAPABILITIES_REQUEST);
    if (BufferSize < MessageSize) {
      printf ("\n");
      return ;
    }
  }

  if (!mParamQuiteMode) {
    if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      printf ("(Flags=0x%08x, CTExponent=0x%02x) ", SpdmRequest->Flags, SpdmRequest->CTExponent);

      if (mParamAllMode) {
        printf ("\n    Flags(");
        DumpEntryFlagsAll (mSpdmRequesterCapabilitiesStringTable, ARRAY_SIZE(mSpdmRequesterCapabilitiesStringTable), SpdmRequest->Flags);
        printf (")");
      }
    } else {
      printf ("() ");
    }
  }

  printf ("\n");

  if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    mSpdmRequesterCapabilitiesFlags = SpdmRequest->Flags;

    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationLocal;
    SpdmSetData (mSpdmContext, SpdmDataCapabilityFlags, &Parameter, &mSpdmRequesterCapabilitiesFlags, sizeof(UINT32));
  }

  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                       MessageSize;
  SPDM_CAPABILITIES_RESPONSE  *SpdmResponse;
  SPDM_DATA_PARAMETER         Parameter;

  printf ("SPDM_CAPABILITIES ");

  MessageSize = sizeof(SPDM_CAPABILITIES_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Flags=0x%08x, CTExponent=0x%02x) ", SpdmResponse->Flags, SpdmResponse->CTExponent);

    if (mParamAllMode) {
      printf ("\n    Flags(");
      DumpEntryFlagsAll (mSpdmResponderCapabilitiesStringTable, ARRAY_SIZE(mSpdmResponderCapabilitiesStringTable), SpdmResponse->Flags);
      printf (")");
    }
  }

  printf ("\n");

  mSpdmResponderCapabilitiesFlags = SpdmResponse->Flags;

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  SpdmSetData (mSpdmContext, SpdmDataCapabilityFlags, &Parameter, &mSpdmResponderCapabilitiesFlags, sizeof(UINT32));

  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmNegotiateAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                                          MessageSize;
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST              *SpdmRequest;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;
  UINT8                                          ExtAlgCount;

  printf ("SPDM_NEGOTIATE_ALGORITHMS ");

  MessageSize = sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  MessageSize += SpdmRequest->ExtAsymCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                 SpdmRequest->ExtHashCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                 SpdmRequest->Header.Param1 * sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(MeasSpec=0x%02x(", SpdmRequest->MeasurementSpecification);
    DumpEntryFlags (mSpdmMeasurementSpecValueStringTable, ARRAY_SIZE(mSpdmMeasurementSpecValueStringTable), SpdmRequest->MeasurementSpecification);
    printf ("), Hash=0x%08x(", SpdmRequest->BaseHashAlgo);
    DumpEntryFlags (mSpdmHashValueStringTable, ARRAY_SIZE(mSpdmHashValueStringTable), SpdmRequest->BaseHashAlgo);
    printf ("), Asym=0x%08x(", SpdmRequest->BaseAsymAlgo);
    DumpEntryFlags (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), SpdmRequest->BaseAsymAlgo);

    if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      StructTable = (VOID *)((UINTN)Buffer +
                              sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                              SpdmRequest->ExtAsymCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                              SpdmRequest->ExtHashCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                              );
      for (Index = 0; Index <SpdmRequest->Header.Param1; Index++) {
        switch (StructTable->AlgType) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
          printf ("), DHE=0x%04x(", StructTable->AlgSupported);
          DumpEntryFlags (mSpdmDheValueStringTable, ARRAY_SIZE(mSpdmDheValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
          printf ("), AEAD=0x%04x(", StructTable->AlgSupported);
          DumpEntryFlags (mSpdmAeadValueStringTable, ARRAY_SIZE(mSpdmAeadValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
          printf ("), ReqAsym=0x%04x(", StructTable->AlgSupported);
          DumpEntryFlags (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          printf ("), KeySchedule=0x%04x(", StructTable->AlgSupported);
          DumpEntryFlags (mSpdmKeyScheduleValueStringTable, ARRAY_SIZE(mSpdmKeyScheduleValueStringTable), StructTable->AlgSupported);
          break;
        }
        ExtAlgCount = StructTable->AlgCount & 0xF;
        StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
      }
    }
    printf (")) ");

    if (mParamAllMode) {
      printf ("\n    ExtHashCount(0x%02x) ExtAsymCount(0x%02x)", SpdmRequest->ExtHashCount, SpdmRequest->ExtAsymCount);
    }
  }

  printf ("\n");

  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                                          MessageSize;
  SPDM_ALGORITHMS_RESPONSE                       *SpdmResponse;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;
  SPDM_DATA_PARAMETER                            Parameter;
  UINT8                                          ExtAlgCount;

  printf ("SPDM_ALGORITHMS ");

  MessageSize = sizeof(SPDM_ALGORITHMS_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  MessageSize += SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                 SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                 SpdmResponse->Header.Param1 * sizeof(SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(MeasSpec=0x%02x(", SpdmResponse->MeasurementSpecificationSel);
    DumpEntryValue (mSpdmMeasurementSpecValueStringTable, ARRAY_SIZE(mSpdmMeasurementSpecValueStringTable), SpdmResponse->MeasurementSpecificationSel);
    printf ("), Hash=0x%08x(", SpdmResponse->BaseHashSel);
    DumpEntryValue (mSpdmHashValueStringTable, ARRAY_SIZE(mSpdmHashValueStringTable), SpdmResponse->BaseHashSel);
    printf ("), MeasHash=0x%08x(", SpdmResponse->MeasurementHashAlgo);
    DumpEntryValue (mSpdmMeasurementHashValueStringTable, ARRAY_SIZE(mSpdmMeasurementHashValueStringTable), SpdmResponse->MeasurementHashAlgo);
    printf ("), Asym=0x%08x(", SpdmResponse->BaseAsymSel);
    DumpEntryValue (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), SpdmResponse->BaseAsymSel);

    if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      StructTable = (VOID *)((UINTN)Buffer +
                              sizeof(SPDM_ALGORITHMS_RESPONSE) +
                              SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                              SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                              );
      for (Index = 0; Index <SpdmResponse->Header.Param1; Index++) {
        switch (StructTable->AlgType) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
          printf ("), DHE=0x%04x(", StructTable->AlgSupported);
          DumpEntryValue (mSpdmDheValueStringTable, ARRAY_SIZE(mSpdmDheValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
          printf ("), AEAD=0x%04x(", StructTable->AlgSupported);
          DumpEntryValue (mSpdmAeadValueStringTable, ARRAY_SIZE(mSpdmAeadValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
          printf ("), ReqAsym=0x%04x(", StructTable->AlgSupported);
          DumpEntryValue (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), StructTable->AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          printf ("), KeySchedule=0x%04x(", StructTable->AlgSupported);
          DumpEntryValue (mSpdmKeyScheduleValueStringTable, ARRAY_SIZE(mSpdmKeyScheduleValueStringTable), StructTable->AlgSupported);
          break;
        }
        ExtAlgCount = StructTable->AlgCount & 0xF;
        StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
      }
    }
    printf (")) ");

    if (mParamAllMode) {
      printf ("\n    ExtHashCount(0x%02x) ExtAsymCount(0x%02x)", SpdmResponse->ExtHashSelCount, SpdmResponse->ExtAsymSelCount);
    }
  }

  printf ("\n");

  mSpdmMeasurementSpec = SpdmResponse->MeasurementSpecificationSel;
  mSpdmMeasurementHashAlgo = SpdmResponse->MeasurementHashAlgo;
  mSpdmBaseAsymAlgo = SpdmResponse->BaseAsymSel;
  mSpdmBaseHashAlgo = SpdmResponse->BaseHashSel;

  if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    StructTable = (VOID *)((UINTN)Buffer +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                            SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                            );
    for (Index = 0; Index <SpdmResponse->Header.Param1; Index++) {
      switch (StructTable->AlgType) {
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        mSpdmDHENamedGroup = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        mSpdmAEADCipherSuite = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        mSpdmReqBaseAsymAlg = StructTable->AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        mSpdmKeySchedule = StructTable->AlgSupported;
        break;
      }
      ExtAlgCount = StructTable->AlgCount & 0xF;
      StructTable = (VOID *)((UINTN)StructTable + sizeof (SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE) + sizeof(UINT32) * ExtAlgCount);
    }
  }

  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationConnection;
  SpdmSetData (mSpdmContext, SpdmDataMeasurementSpec, &Parameter, &mSpdmMeasurementSpec, sizeof(UINT8));
  SpdmSetData (mSpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &mSpdmMeasurementHashAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &mSpdmBaseAsymAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataBaseHashAlgo, &Parameter, &mSpdmBaseHashAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataDHENamedGroup, &Parameter, &mSpdmDHENamedGroup, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataAEADCipherSuite, &Parameter, &mSpdmAEADCipherSuite, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &mSpdmReqBaseAsymAlg, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataKeySchedule, &Parameter, &mSpdmKeySchedule, sizeof(UINT16));

  SpdmAppendMessageA (mSpdmContext, Buffer, MessageSize);
}

VOID
DumpSpdmGetDigests (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                     MessageSize;

  printf ("SPDM_GET_DIGESTS ");

  MessageSize = sizeof(SPDM_GET_DIGESTS_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");
}

VOID
DumpSpdmDigests (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DIGESTS_RESPONSE  *SpdmResponse;
  UINTN                  MessageSize;
  UINTN                  HashSize;
  UINTN                  SlotCount;
  UINTN                  Index;
  UINT8                  *Digest;

  printf ("SPDM_DIGESTS ");

  MessageSize = sizeof(SPDM_DIGESTS_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  SlotCount = 0;
  for (Index = 0; Index < 8; Index++) {
    if (((1 << Index) & SpdmResponse->Header.Param2) != 0) {
      SlotCount ++;
    }
  }

  HashSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  MessageSize += SlotCount * HashSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(SlotMask=0x%02x) ", SpdmResponse->Header.Param2);

    if (mParamAllMode) {
      Digest = (VOID *)(SpdmResponse + 1);
      for (Index = 0; Index < SlotCount; Index++) {
        printf ("\n    Digest_%d(", (UINT32)Index);
        DumpData (Digest, HashSize);
        printf (")");
        Digest += HashSize;
      }
    }
  }

  printf ("\n");
}

VOID
DumpSpdmGetCertificate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_GET_CERTIFICATE_REQUEST  *SpdmRequest;
  UINTN                         MessageSize;

  printf ("SPDM_GET_CERTIFICATE ");

  MessageSize = sizeof(SPDM_GET_CERTIFICATE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    printf ("(SlotID=0x%02x, Offset=0x%x, Length=0x%x) ", SpdmRequest->Header.Param1, SpdmRequest->Offset, SpdmRequest->Length);
  }

  mCachedSpdmCertChainBufferOffset = SpdmRequest->Offset;

  printf ("\n");
}

VOID
DumpSpdmCertificate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_CERTIFICATE_RESPONSE  *SpdmResponse;
  UINTN                      MessageSize;
  VOID                       *CertChain;
  UINTN                      CertChainSize;
  UINTN                      HashSize;
  SPDM_CERT_CHAIN            *SpdmCertChain;
  UINT8                      *RootHash;

  printf ("SPDM_CERTIFICATE ");

  MessageSize = sizeof(SPDM_CERTIFICATE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  MessageSize += SpdmResponse->PortionLength;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(SlotID=0x%02x, PortLen=0x%x, RemLen=0x%x) ", SpdmResponse->Header.Param1, SpdmResponse->PortionLength, SpdmResponse->RemainderLength);
  }

  if (mCachedSpdmCertChainBufferOffset + SpdmResponse->PortionLength > MAX_SPDM_CERT_CHAIN_SIZE) {
    printf ("SPDM cert_chain is too larger. Please increase MAX_SPDM_CERT_CHAIN_SIZE and rebuild.\n");
    exit (0);
  }
  memcpy (
    (UINT8 *)mSpdmCertChainBuffer + mCachedSpdmCertChainBufferOffset,
    (SpdmResponse + 1),
    SpdmResponse->PortionLength
    );
  mSpdmCertChainBufferSize = mCachedSpdmCertChainBufferOffset + SpdmResponse->PortionLength;

  HashSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  if (SpdmResponse->RemainderLength == 0) {
    if (mSpdmCertChainBufferSize <= sizeof(SPDM_CERT_CHAIN) + HashSize) {
      printf ("\n");
      return ;
    }

    SpdmCertChain = mSpdmCertChainBuffer;
    if (SpdmCertChain->Length != mSpdmCertChainBufferSize) {
      printf ("\n");
      return ;
    }
  }

  if (!mParamQuiteMode) {
    if (mParamAllMode) {
      if (SpdmResponse->RemainderLength == 0) {
        SpdmCertChain = mSpdmCertChainBuffer;
        printf ("\n    SpdmCertChainSize(0x%04x)", SpdmCertChain->Length);

        RootHash = (VOID *)(SpdmCertChain + 1);
        printf ("\n    RootHash(");
        DumpData (RootHash, HashSize);
        printf (")");

        CertChain = (UINT8 *)mSpdmCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
        CertChainSize = mSpdmCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);
        printf ("\n    CertChain(\n");
        DumpHex (CertChain, CertChainSize);
        printf ("    )");
      }
    }
  }

  if (SpdmResponse->RemainderLength == 0) {
    CertChain = (UINT8 *)mSpdmCertChainBuffer + sizeof(SPDM_CERT_CHAIN) + HashSize;
    CertChainSize = mSpdmCertChainBufferSize - (sizeof(SPDM_CERT_CHAIN) + HashSize);

    if (mEncapsulated) {
      if (mParamOutReqCertChainFileName != NULL) {
        if (!WriteOutputFile (mParamOutReqCertChainFileName, CertChain, CertChainSize)) {
          printf ("Fail to write out_req_cert_chain\n");
        }
      }
      if (mRequesterCertChainBuffer == NULL || mRequesterCertChainBufferSize == 0) {
        mRequesterCertChainBuffer = malloc (CertChainSize);
        if (mRequesterCertChainBuffer != NULL) {
          memcpy (mRequesterCertChainBuffer, CertChain, CertChainSize);
          mRequesterCertChainBufferSize = CertChainSize;
        }
      }
    } else {
      if (mParamOutRspCertChainFileName != NULL) {
        if (!WriteOutputFile (mParamOutRspCertChainFileName, CertChain, CertChainSize)) {
          printf ("Fail to write out_rsp_cert_chain\n");
        }
      }
      if (mResponderCertChainBuffer == NULL || mResponderCertChainBufferSize == 0) {
        mResponderCertChainBuffer = malloc (CertChainSize);
        if (mResponderCertChainBuffer != NULL) {
          memcpy (mResponderCertChainBuffer, CertChain, CertChainSize);
          mResponderCertChainBufferSize = CertChainSize;
        }
      }
    }
  }

  printf ("\n");
}

VOID
DumpSpdmChallenge (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_CHALLENGE_REQUEST  *SpdmRequest;
  UINTN                   MessageSize;

  printf ("SPDM_CHALLENGE ");

  MessageSize = sizeof(SPDM_CHALLENGE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  mCachedMeasurementSummaryHashType = SpdmRequest->Header.Param2;

  if (!mParamQuiteMode) {
    printf ("(SlotID=0x%02x, HashType=0x%02x(", SpdmRequest->Header.Param1, SpdmRequest->Header.Param2);
    DumpEntryValue (mSpdmRequestHashTypeStringTable, ARRAY_SIZE(mSpdmRequestHashTypeStringTable), SpdmRequest->Header.Param2);
    printf (")) ");

    if (mParamAllMode) {
      printf ("\n    Nonce(");
      DumpData (SpdmRequest->Nonce, 32);
      printf (")");
    }
  }

  printf ("\n");
}

VOID
DumpSpdmChallengeAuth (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_CHALLENGE_AUTH_RESPONSE  *SpdmResponse;
  UINTN                         MessageSize;
  UINTN                         HashSize;
  UINTN                         MeasurementSummaryHashSize;
  UINTN                         SignatureSize;
  UINT16                        OpaqueLength;
  UINT8                         *CertChainHash;
  UINT8                         *Nonce;
  UINT8                         *MeasurementSummaryHash;
  UINT8                         *OpaqueData;
  UINT8                         *Signature;

  printf ("SPDM_CHALLENGE_AUTH ");

  HashSize = GetSpdmHashSize (mSpdmBaseHashAlgo);
  SignatureSize = GetSpdmAsymSignatureSize (mSpdmBaseAsymAlgo);
  MeasurementSummaryHashSize = SpdmDumpGetMeasurementSummaryHashSize (mCachedMeasurementSummaryHashType);

  MessageSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + HashSize + 32 + MeasurementSummaryHashSize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + HashSize + 32 + MeasurementSummaryHashSize);
  MessageSize += OpaqueLength + SignatureSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Attr=0x%02x(",
      SpdmResponse->Header.Param1
      );
    DumpEntryFlags (mSpdmChallengeAuthAttributeStringTable, ARRAY_SIZE(mSpdmChallengeAuthAttributeStringTable), SpdmResponse->Header.Param1 & 0xF0);
    printf (", SlotID=0x%02x), SlotMask=0x%02x) ",
      SpdmResponse->Header.Param1 & 0xF,
      SpdmResponse->Header.Param2
      );

    if (mParamAllMode) {
      CertChainHash = (VOID *)(SpdmResponse + 1);
      printf ("\n    CertChainHash(");
      DumpData (CertChainHash, HashSize);
      printf (")");
      Nonce = CertChainHash + HashSize;
      printf ("\n    Nonce(");
      DumpData (Nonce, 32);
      printf (")");
      MeasurementSummaryHash = Nonce + 32;
      if (MeasurementSummaryHashSize != 0) {
        printf ("\n    MeasurementSummaryHash(");
        DumpData (MeasurementSummaryHash, MeasurementSummaryHashSize);
        printf (")");
      }
      OpaqueLength = *(UINT16 *)(MeasurementSummaryHash + MeasurementSummaryHashSize);
      OpaqueData = MeasurementSummaryHash + MeasurementSummaryHashSize + sizeof(UINT16);
      printf ("\n    OpaqueData(");
      DumpData (OpaqueData, OpaqueLength);
      printf (")");
      DumpSpdmOpaqueData (OpaqueData, OpaqueLength);
      Signature = OpaqueData + OpaqueLength;
      printf ("\n    Signature(");
      DumpData (Signature, SignatureSize);
      printf (")");
    }
  }

  printf ("\n");
}

VOID
DumpSpdmGetMeasurements (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_GET_MEASUREMENTS_REQUEST  *SpdmRequest;
  UINTN                          MessageSize;
  BOOLEAN                        IncludeSignature;

  printf ("SPDM_GET_MEASUREMENTS ");

  MessageSize = OFFSET_OF(SPDM_GET_MEASUREMENTS_REQUEST, Nonce);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  IncludeSignature = ((SpdmRequest->Header.Param1 & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0);
  if (IncludeSignature) {
    if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      MessageSize = sizeof(SPDM_GET_MEASUREMENTS_REQUEST);
    } else {
      MessageSize = OFFSET_OF(SPDM_GET_MEASUREMENTS_REQUEST, SlotIDParam);
    }
  }
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  mCachedGetMeasurementRequestAttribute = SpdmRequest->Header.Param1;
  mCachedGetMeasurementOperation = SpdmRequest->Header.Param2;

  if (!mParamQuiteMode) {
    printf ("(Attr=0x%02x(", SpdmRequest->Header.Param1);
    DumpEntryFlags (mSpdmMeasurementAttributeStringTable, ARRAY_SIZE(mSpdmMeasurementAttributeStringTable), SpdmRequest->Header.Param1);
    printf ("), MeasOp=0x%02x", SpdmRequest->Header.Param2);
    switch (SpdmRequest->Header.Param2) {
    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
      printf ("(TotalNum)");
      break;
    case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
      printf ("(All)");
      break;
    }
    if (IncludeSignature && (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11)) {
      printf (", SlotID=0x%02x", SpdmRequest->SlotIDParam);
    }
    printf (") ");

    if (mParamAllMode) {
      if (IncludeSignature) {
        printf ("\n    Nonce(");
        DumpData (SpdmRequest->Nonce, 32);
        printf (")");
      }
    }
  }

  printf ("\n");
}

VOID
DumpSpdmMeasurementRecord (
  IN UINT8   NumberOfBlocks,
  IN VOID    *MeasurementRecord,
  IN UINT32  MeasurementRecordLength
  )
{
  SPDM_MEASUREMENT_BLOCK_DMTF           *DmtfBlock;
  UINTN                                 Index;
  UINTN                                 EndOfBlock;
  UINTN                                 EndOfRecord;

  EndOfRecord = (UINTN)MeasurementRecord + MeasurementRecordLength;

  DmtfBlock = (VOID *)MeasurementRecord;
  for (Index = 0; Index < NumberOfBlocks; Index++) {
    if ((UINTN)DmtfBlock + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF) > EndOfRecord) {
      break;
    }
    if (DmtfBlock->MeasurementBlockCommonHeader.MeasurementSpecification != SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
      break;
    }
    if (DmtfBlock->MeasurementBlockCommonHeader.MeasurementSize != DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize + sizeof(SPDM_MEASUREMENT_BLOCK_DMTF_HEADER)) {
      break;
    }
    EndOfBlock = (UINTN)DmtfBlock + DmtfBlock->MeasurementBlockCommonHeader.MeasurementSize + sizeof(SPDM_MEASUREMENT_BLOCK_COMMON_HEADER);
    if (EndOfBlock > EndOfRecord) {
      break;
    }

    printf ("\n      MeasurementRecord_%d(", (UINT32)Index);
    printf ("\n        CommonHeader(Index=0x%02x, MeasSpec=0x%02x(",
      DmtfBlock->MeasurementBlockCommonHeader.Index,
      DmtfBlock->MeasurementBlockCommonHeader.MeasurementSpecification
      );
    DumpEntryFlags (mSpdmMeasurementSpecValueStringTable, ARRAY_SIZE(mSpdmMeasurementSpecValueStringTable), DmtfBlock->MeasurementBlockCommonHeader.MeasurementSpecification);
    printf ("), Size=0x%04x)",
      DmtfBlock->MeasurementBlockCommonHeader.MeasurementSize
      );

    printf ("\n        DmtfHeader(Type=0x%02x(",
      DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType
      );
    DumpEntryValue (mSpdmMeasurementTypeValueStringTable, ARRAY_SIZE(mSpdmMeasurementTypeValueStringTable), DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType & SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK);
    if (DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueType & SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) {
      printf (", RawBitStream");
    }
    printf ("), Size=0x%04x)",
      DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize
      );

    printf ("\n        Value(");
    DumpData ((VOID *)(DmtfBlock + 1), DmtfBlock->MeasurementBlockDmtfHeader.DMTFSpecMeasurementValueSize);
    printf (")");
    printf ("\n        )");

    DmtfBlock = (VOID *)EndOfBlock;
  }
}

VOID
DumpSpdmMeasurements (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_MEASUREMENTS_RESPONSE  *SpdmResponse;
  UINTN                       MessageSize;
  UINT32                      MeasurementRecordLength;
  UINTN                       SignatureSize;
  UINT16                      OpaqueLength;
  BOOLEAN                     IncludeSignature;
  UINT8                       *MeasurementRecord;
  UINT8                       *Nonce;
  UINT8                       *OpaqueData;
  UINT8                       *Signature;

  printf ("SPDM_MEASUREMENTS ");

  MessageSize = sizeof(SPDM_MEASUREMENTS_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  IncludeSignature = ((mCachedGetMeasurementRequestAttribute & SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) != 0);

  SpdmResponse = Buffer;

  MeasurementRecordLength = SpdmReadUint24 (SpdmResponse->MeasurementRecordLength);
  MessageSize += MeasurementRecordLength;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (IncludeSignature) {
    SignatureSize = GetSpdmAsymSignatureSize (mSpdmBaseAsymAlgo);

    MessageSize += 32 + sizeof(UINT16);
    if (BufferSize < MessageSize) {
      printf ("\n");
      return ;
    }

    OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_MEASUREMENTS_RESPONSE) + MeasurementRecordLength + 32);
    MessageSize += OpaqueLength + SignatureSize;
    if (BufferSize < MessageSize) {
      printf ("\n");
      return ;
    }
  }

  if (!mParamQuiteMode) {
    if (mCachedGetMeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
      printf ("(TotalMeasIndex=0x%02x", SpdmResponse->Header.Param1);
      if (IncludeSignature) {
        printf (", SlotID=0x%02x", SpdmResponse->Header.Param2);
      }
      printf (") ");
    } else {
      printf ("(NumOfBlocks=0x%x, MeasRecordLen=0x%x", SpdmResponse->NumberOfBlocks, MeasurementRecordLength);
      if (IncludeSignature) {
        printf (", SlotID=0x%02x", SpdmResponse->Header.Param2);
      }
      printf (") ");
    }

    if (mParamAllMode) {
      MeasurementRecord = (VOID *)(SpdmResponse + 1);
      if (mCachedGetMeasurementOperation != SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
        printf ("\n    MeasurementRecord(");
        DumpData (MeasurementRecord, MeasurementRecordLength);
        printf (")");

        DumpSpdmMeasurementRecord (SpdmResponse->NumberOfBlocks, MeasurementRecord, MeasurementRecordLength);
      }
      if (IncludeSignature) {
        Nonce = MeasurementRecord + MeasurementRecordLength;
        printf ("\n    Nonce(");
        DumpData (Nonce, 32);
        printf (")");
        OpaqueLength = *(UINT16 *)(Nonce + 32);
        OpaqueData = Nonce + 32 + sizeof(UINT16);
        printf ("\n    OpaqueData(");
        DumpData (OpaqueData, OpaqueLength);
        printf (")");
        DumpSpdmOpaqueData (OpaqueData, OpaqueLength);
        Signature = OpaqueData + OpaqueLength;
        printf ("\n    Signature(");
        DumpData (Signature, SignatureSize);
        printf (")");
      } else {
        OpaqueLength = *(UINT16 *)(MeasurementRecord + MeasurementRecordLength);
        OpaqueData = MeasurementRecord + MeasurementRecordLength + sizeof(UINT16);
        printf ("\n    OpaqueData(");
        DumpData (OpaqueData, OpaqueLength);
        printf (")");
        DumpSpdmOpaqueData (OpaqueData, OpaqueLength);
      }
    }
  }

  printf ("\n");
}

VOID
DumpSpdmRespondIfReady (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_RESPONSE_IF_READY_REQUEST  *SpdmRequest;

  printf ("SPDM_RESPOND_IF_READY ");
  if (BufferSize < sizeof(SPDM_RESPONSE_IF_READY_REQUEST)) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    printf ("(ReqCode=0x%02x, Token=0x%02x) ", SpdmRequest->Header.Param1, SpdmRequest->Header.Param2);
  }

  printf ("\n");
}

VOID
DumpSpdmError (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_ERROR_RESPONSE  *SpdmResponse;

  printf ("SPDM_ERROR ");

  if (BufferSize < sizeof(SPDM_ERROR_RESPONSE)) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(ErrCode=0x%02x, ErrData=0x%02x) ", SpdmResponse->Header.Param1, SpdmResponse->Header.Param2);

    if (SpdmResponse->Header.Param1 == SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
      if (BufferSize >= sizeof(SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY)) {
        SPDM_ERROR_RESPONSE_DATA_RESPONSE_NOT_READY  *SpdmResponseNotReady;

        SpdmResponseNotReady = Buffer;
        printf ("(ReqCode=0x%02x, Token=0x%02x, RDTExponent=0x%02x, RDTM=0x%02x) ",
          SpdmResponseNotReady->ExtendErrorData.RequestCode,
          SpdmResponseNotReady->ExtendErrorData.Token,
          SpdmResponseNotReady->ExtendErrorData.RDTExponent,
          SpdmResponseNotReady->ExtendErrorData.RDTM
          );
      }
    }
  }

  if (SpdmResponse->Header.Param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) {
    SpdmFreeSessionId (mSpdmContext, mCurrentSessionId);
  }

  printf ("\n");
}

VOID
DumpSpdmVendorDefinedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_VENDOR_DEFINED_REQUEST_MSG  *SpdmRequest;
  UINTN                            HeaderSize;

  printf ("SPDM_VENDOR_DEFINED_REQUEST ");

  if (BufferSize < sizeof(SPDM_VENDOR_DEFINED_REQUEST_MSG)) {
    printf ("\n");
    return ;
  }
  HeaderSize = OFFSET_OF(SPDM_VENDOR_DEFINED_REQUEST_MSG, StandardID);

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    printf ("(StandID=0x%04x) ", SpdmRequest->StandardID);
  }

  if (mParamDumpVendorApp) {
    DumpDispatchMessage (mSpdmVendorDispatch, ARRAY_SIZE(mSpdmVendorDispatch), SpdmRequest->StandardID, (UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
  } else {
    printf ("\n");
  }
}

VOID
DumpSpdmVendorDefinedResponse (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_VENDOR_DEFINED_RESPONSE_MSG  *SpdmResponse;
  UINTN                             HeaderSize;

  printf ("SPDM_VENDOR_DEFINED_RESPONSE ");

  if (BufferSize < sizeof(SPDM_VENDOR_DEFINED_REQUEST_MSG)) {
    printf ("\n");
    return ;
  }
  HeaderSize = OFFSET_OF(SPDM_VENDOR_DEFINED_REQUEST_MSG, StandardID);

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(StandID=0x%04x) ", SpdmResponse->StandardID);
  }

  if (mParamDumpVendorApp) {
    DumpDispatchMessage (mSpdmVendorDispatch, ARRAY_SIZE(mSpdmVendorDispatch), SpdmResponse->StandardID, (UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
  } else {
    printf ("\n");
  }
}

VOID
DumpSpdmKeyExchange (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_EXCHANGE_REQUEST  *SpdmRequest;
  UINTN                      MessageSize;
  UINTN                      DheKeySize;
  UINT16                     OpaqueLength;
  UINT8                      *ExchangeData;
  UINT8                      *OpaqueData;

  printf ("SPDM_KEY_EXCHANGE ");

  MessageSize = sizeof(SPDM_KEY_EXCHANGE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  DheKeySize = GetSpdmDhePubKeySize (mSpdmDHENamedGroup);
  MessageSize += DheKeySize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DheKeySize);
  MessageSize += OpaqueLength;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  mCachedMeasurementSummaryHashType = SpdmRequest->Header.Param1;

  if (!mParamQuiteMode) {
    printf ("(HashType=0x%02x(", SpdmRequest->Header.Param1);
    DumpEntryValue (mSpdmRequestHashTypeStringTable, ARRAY_SIZE(mSpdmRequestHashTypeStringTable), SpdmRequest->Header.Param1);
    printf ("), SlotID=0x%02x, ReqSessionID=0x%04x) ", SpdmRequest->Header.Param2, SpdmRequest->ReqSessionID);

    if (mParamAllMode) {
      printf ("\n    RandomData(");
      DumpData (SpdmRequest->RandomData, 32);
      printf (")");
      ExchangeData = (VOID *)(SpdmRequest + 1);
      printf ("\n    ExchangeData(");
      DumpData (ExchangeData, DheKeySize);
      printf (")");
      OpaqueLength = *(UINT16 *)((UINT8 *)ExchangeData + DheKeySize);
      OpaqueData = (VOID *)((UINT8 *)ExchangeData + DheKeySize + sizeof(UINT16));
      printf ("\n    OpaqueData(");
      DumpData (OpaqueData, OpaqueLength);
      printf (")");
      DumpSpdmOpaqueData (OpaqueData, OpaqueLength);
    }
  }

  printf ("\n");

  mCachedSessionId = SpdmRequest->ReqSessionID << 16;
  memcpy (mSpdmLastMessageBuffer, Buffer, MessageSize);
  mSpdmLastMessageBufferSize = MessageSize;
}

VOID
DumpSpdmKeyExchangeRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_EXCHANGE_RESPONSE  *SpdmResponse;
  UINTN                       MessageSize;
  UINTN                       DheKeySize;
  UINTN                       MeasurementSummaryHashSize;
  UINTN                       SignatureSize;
  UINTN                       HmacSize;
  UINT16                      OpaqueLength;
  BOOLEAN                     IncludeHmac;
  UINT8                       *ExchangeData;
  UINT8                       *MeasurementSummaryHash;
  UINT8                       *OpaqueData;
  UINT8                       *Signature;
  UINT8                       *VerifyData;
  UINT8                       TH1HashData[64];
  SPDM_DATA_PARAMETER         Parameter;
  UINT8                       MutAuthRequested;

  printf ("SPDM_KEY_EXCHANGE_RSP ");

  MessageSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  DheKeySize = GetSpdmDhePubKeySize (mSpdmDHENamedGroup);
  SignatureSize = GetSpdmAsymSignatureSize (mSpdmBaseAsymAlgo);
  MeasurementSummaryHashSize = SpdmDumpGetMeasurementSummaryHashSize (mCachedMeasurementSummaryHashType);
  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  MessageSize += DheKeySize + MeasurementSummaryHashSize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_KEY_EXCHANGE_RESPONSE) + DheKeySize + MeasurementSummaryHashSize);
  MessageSize += OpaqueLength + SignatureSize;
  IncludeHmac = ((mSpdmResponderCapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) ||
                ((mSpdmRequesterCapabilitiesFlags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0);
  if (IncludeHmac) {
    MessageSize += HmacSize;
  }
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(Heart=0x%02x, RspSessionID=0x%04x, MutAuth=0x%02x(", SpdmResponse->Header.Param1, SpdmResponse->RspSessionID, SpdmResponse->MutAuthRequested);
    DumpEntryFlags (mSpdmKeyExchangeMutAuthStringTable, ARRAY_SIZE(mSpdmKeyExchangeMutAuthStringTable), SpdmResponse->MutAuthRequested);
    printf ("), ReqSlotID=0x%02x) ", SpdmResponse->ReqSlotIDParam);

    if (mParamAllMode) {
      printf ("\n    RandomData(");
      DumpData (SpdmResponse->RandomData, 32);
      printf (")");
      ExchangeData = (VOID *)(SpdmResponse + 1);
      printf ("\n    ExchangeData(");
      DumpData (ExchangeData, DheKeySize);
      printf (")");
      MeasurementSummaryHash = ExchangeData + DheKeySize;
      if (MeasurementSummaryHashSize != 0) {
        printf ("\n    MeasurementSummaryHash(");
        DumpData (MeasurementSummaryHash, MeasurementSummaryHashSize);
        printf (")");
      }
      OpaqueLength = *(UINT16 *)((UINT8 *)MeasurementSummaryHash + MeasurementSummaryHashSize);
      OpaqueData = (VOID *)((UINT8 *)MeasurementSummaryHash + MeasurementSummaryHashSize + sizeof(UINT16));
      printf ("\n    OpaqueData(");
      DumpData (OpaqueData, OpaqueLength);
      printf (")");
      DumpSpdmOpaqueData (OpaqueData, OpaqueLength);
      Signature = OpaqueData + OpaqueLength;
      printf ("\n    Signature(");
      DumpData (Signature, SignatureSize);
      printf (")");
      if (IncludeHmac) {
        VerifyData = Signature + SignatureSize;
        printf ("\n    VerifyData(");
        DumpData (VerifyData, HmacSize);
        printf (")");
      }
    }
  }

  printf ("\n");

  mCachedSessionId = mCachedSessionId | SpdmResponse->RspSessionID;
  // double check if current is occupied
  if (SpdmGetSessionInfoViaSessionId (mSpdmContext, mCachedSessionId) != NULL) {
    // this might happen if a session is terminated without EndSession
    SpdmFreeSessionId (mSpdmContext, mCachedSessionId);
  }
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId, FALSE);
  ASSERT (mCurrentSessionInfo != NULL);
  if (mCurrentSessionInfo == NULL) {
    return ;
  }
  mCurrentSessionId = mCachedSessionId;

  MutAuthRequested = SpdmResponse->MutAuthRequested;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
  SpdmSetData (mSpdmContext, SpdmDataSessionMutAuthRequested, &Parameter, &MutAuthRequested, sizeof(MutAuthRequested));

  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);
  SpdmAppendMessageK (mCurrentSessionInfo, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  if (IncludeHmac) {
    SpdmAppendMessageK (mCurrentSessionInfo, Buffer, MessageSize - HmacSize);
  } else {
    SpdmAppendMessageK (mCurrentSessionInfo, Buffer, MessageSize);
  }

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionHandshakeKey[%x]\n", mCurrentSessionId));
  if (SpdmDumpSessionDataProvision (mSpdmContext, mCurrentSessionId, FALSE, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  SpdmCalculateTH1Hash (mSpdmContext, mCurrentSessionInfo, TRUE, TH1HashData);
  SpdmGenerateSessionHandshakeKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TH1HashData);
  if (IncludeHmac) {
    SpdmAppendMessageK (mCurrentSessionInfo, (UINT8 *)Buffer + MessageSize - HmacSize, HmacSize);
  }

  SpdmSecuredMessageSetSessionState (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmSessionStateHandshaking);
}

VOID
DumpSpdmFinish (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_FINISH_REQUEST  *SpdmRequest;
  UINTN                MessageSize;
  UINTN                SignatureSize;
  UINTN                HmacSize;
  BOOLEAN              IncludeSignature;
  UINT8                *Signature;
  UINT8                *VerifyData;

  printf ("SPDM_FINISH ");

  MessageSize = sizeof(SPDM_FINISH_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  SignatureSize = GetSpdmReqAsymSignatureSize (mSpdmReqBaseAsymAlg);
  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  IncludeSignature = ((SpdmRequest->Header.Param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0);
  if (IncludeSignature) {
    MessageSize += SignatureSize;
  }
  MessageSize += HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(Attr=0x%02x (SigIncl=%x), ReqSlotID=0x%02x) ",
      SpdmRequest->Header.Param1,
      ((SpdmRequest->Header.Param1 & SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0) ? 1 : 0,
      SpdmRequest->Header.Param2
      );

    if (mParamAllMode) {
      if (IncludeSignature) {
        Signature = (VOID *)(SpdmRequest + 1);
        printf ("\n    Signature(");
        DumpData (Signature, SignatureSize);
        printf (")");
        VerifyData = Signature + SignatureSize;
      } else {
        VerifyData = (VOID *)(SpdmRequest + 1);
      }
      printf ("\n    VerifyData(");
      DumpData (VerifyData, HmacSize);
      printf (")");
    }
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  SpdmAppendMessageF (mCurrentSessionInfo, Buffer, MessageSize);
}

VOID
DumpSpdmFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_FINISH_RESPONSE  *SpdmResponse;
  UINTN                 MessageSize;
  UINTN                 HmacSize;
  BOOLEAN               IncludeHmac;
  UINT8                 *VerifyData;
  UINT8                 TH2HashData[64];

  printf ("SPDM_FINISH_RSP ");

  MessageSize = sizeof(SPDM_FINISH_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);

  IncludeHmac = ((mSpdmResponderCapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0) &&
                ((mSpdmRequesterCapabilitiesFlags & SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) != 0);
  if (IncludeHmac) {
    MessageSize += HmacSize;
  }
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");

    if (mParamAllMode) {
      if (IncludeHmac) {
        VerifyData = (VOID *)(SpdmResponse + 1);
        printf ("\n    VerifyData(");
        DumpData (VerifyData, HmacSize);
        printf (")");
      }
    }
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  if (mCurrentSessionInfo == NULL) {
    return ;
  }
  SpdmAppendMessageF (mCurrentSessionInfo, Buffer, MessageSize);

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", mCurrentSessionId));
  if (SpdmDumpSessionDataProvision (mSpdmContext, mCurrentSessionId, TRUE, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  if (SpdmDumpSessionDataCheck (mSpdmContext, mCurrentSessionId, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  SpdmCalculateTH2Hash (mSpdmContext, mCurrentSessionInfo, TRUE, TH2HashData);
  SpdmGenerateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TH2HashData);
  SpdmSecuredMessageSetSessionState (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmSessionStateEstablished);
}

VOID
DumpSpdmPskExchange (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_PSK_EXCHANGE_REQUEST  *SpdmRequest;
  UINTN                      MessageSize;
  UINT8                      *PSKHint;
  UINT8                      *RequesterContext;
  UINT8                      *OpaqueData;

  printf ("SPDM_PSK_EXCHANGE ");

  MessageSize = sizeof(SPDM_PSK_EXCHANGE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  MessageSize += SpdmRequest->PSKHintLength + SpdmRequest->RequesterContextLength + SpdmRequest->OpaqueLength;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  mCachedMeasurementSummaryHashType = SpdmRequest->Header.Param1;

  if (!mParamQuiteMode) {
    printf ("(HashType=0x%02x(", SpdmRequest->Header.Param1);
    DumpEntryValue (mSpdmRequestHashTypeStringTable, ARRAY_SIZE(mSpdmRequestHashTypeStringTable), SpdmRequest->Header.Param1);
    printf ("), ReqSessionID=0x%04x, PSKHint=", SpdmRequest->ReqSessionID);
    PSKHint = (VOID *)(SpdmRequest + 1);
    DumpHexStr (PSKHint, SpdmRequest->PSKHintLength);
    printf (") ");

    if (mParamAllMode) {
      RequesterContext = PSKHint + SpdmRequest->PSKHintLength;
      printf ("\n    Context(");
      DumpData (RequesterContext, SpdmRequest->RequesterContextLength);
      printf (")");
      OpaqueData = RequesterContext + SpdmRequest->RequesterContextLength;
      printf ("\n    OpaqueData(");
      DumpData (OpaqueData, SpdmRequest->OpaqueLength);
      printf (")");
      DumpSpdmOpaqueData (OpaqueData, SpdmRequest->OpaqueLength);
    }
  }

  printf ("\n");

  mCachedSessionId = SpdmRequest->ReqSessionID << 16;
  memcpy (mSpdmLastMessageBuffer, Buffer, MessageSize);
  mSpdmLastMessageBufferSize = MessageSize;
}

VOID
DumpSpdmPskExchangeRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_PSK_EXCHANGE_RESPONSE  *SpdmResponse;
  UINTN                       MessageSize;
  UINTN                       MeasurementSummaryHashSize;
  UINTN                       HmacSize;
  UINT8                       *MeasurementSummaryHash;
  UINT8                       *ResponderContext;
  UINT8                       *OpaqueData;
  UINT8                       *VerifyData;
  UINT8                       TH1HashData[64];
  UINT8                       TH2HashData[64];
  SPDM_DATA_PARAMETER         Parameter;
  BOOLEAN                     UsePsk;

  printf ("SPDM_PSK_EXCHANGE_RSP ");

  MessageSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  MeasurementSummaryHashSize = SpdmDumpGetMeasurementSummaryHashSize (mCachedMeasurementSummaryHashType);
  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);
  MessageSize += MeasurementSummaryHashSize + SpdmResponse->ResponderContextLength + SpdmResponse->OpaqueLength + HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(Heart=0x%02x, RspSessionID=0x%04x) ", SpdmResponse->Header.Param1, SpdmResponse->RspSessionID);

    if (mParamAllMode) {
      MeasurementSummaryHash = (VOID *)(SpdmResponse + 1);
      if (MeasurementSummaryHashSize != 0) {
        printf ("\n    MeasurementSummaryHash(");
        DumpData (MeasurementSummaryHash, MeasurementSummaryHashSize);
        printf (")");
      }
      ResponderContext = MeasurementSummaryHash + MeasurementSummaryHashSize;
      printf ("\n    Context(");
      DumpData (ResponderContext, SpdmResponse->ResponderContextLength);
      printf (")");
      OpaqueData = ResponderContext + SpdmResponse->ResponderContextLength;
      printf ("\n    OpaqueData(");
      DumpData (OpaqueData, SpdmResponse->OpaqueLength);
      printf (")");
      DumpSpdmOpaqueData (OpaqueData, SpdmResponse->OpaqueLength);
      VerifyData = OpaqueData + SpdmResponse->OpaqueLength;
      printf ("\n    VerifyData(");
      DumpData (VerifyData, HmacSize);
      printf (")");
    }
  }

  printf ("\n");

  mCachedSessionId = mCachedSessionId | SpdmResponse->RspSessionID;
  // double check if current is occupied
  if (SpdmGetSessionInfoViaSessionId (mSpdmContext, mCachedSessionId) != NULL) {
    // this might happen if a session is terminated without EndSession
    SpdmFreeSessionId (mSpdmContext, mCachedSessionId);
  }
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId, TRUE);
  ASSERT (mCurrentSessionInfo != NULL);
  if (mCurrentSessionInfo == NULL) {
    return ;
  }
  mCurrentSessionId = mCachedSessionId;

  SpdmAppendMessageK (mCurrentSessionInfo, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  SpdmAppendMessageK (mCurrentSessionInfo, Buffer, MessageSize - HmacSize);

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionHandshakeKey[%x]\n", mCurrentSessionId));
  if (SpdmDumpSessionDataProvision (mSpdmContext, mCurrentSessionId, FALSE, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  SpdmCalculateTH1Hash (mSpdmContext, mCurrentSessionInfo, TRUE, TH1HashData);
  SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), FALSE);

  UsePsk = FALSE;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
  SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

  SpdmGenerateSessionHandshakeKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TH1HashData);

  UsePsk = TRUE;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
  SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

  SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TRUE);
  SpdmAppendMessageK (mCurrentSessionInfo, (UINT8 *)Buffer + MessageSize - HmacSize, HmacSize);

  SpdmSecuredMessageSetSessionState (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmSessionStateHandshaking);

  if ((mSpdmResponderCapabilitiesFlags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT) == 0) {
    // No need to receive PSK_FINISH, enter application phase directly.

    SpdmCalculateTH2Hash (mSpdmContext, mCurrentSessionInfo, TRUE, TH2HashData);
    SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), FALSE);

    UsePsk = FALSE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationSession;
    *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
    SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

    SpdmGenerateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TH2HashData);

    UsePsk = TRUE;
    ZeroMem (&Parameter, sizeof(Parameter));
    Parameter.Location = SpdmDataLocationSession;
    *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
    SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

    SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TRUE);
    SpdmSecuredMessageSetSessionState (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmSessionStateEstablished);
  }
}

VOID
DumpSpdmPskFinish (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_PSK_FINISH_REQUEST     *SpdmRequest;
  UINTN                       MessageSize;
  UINTN                       HmacSize;
  UINT8                       *VerifyData;

  printf ("SPDM_PSK_FINISH ");

  MessageSize = sizeof(SPDM_PSK_FINISH_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  HmacSize = GetSpdmHashSize (mSpdmBaseHashAlgo);
  MessageSize += HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");

    if (mParamAllMode) {
      VerifyData = (VOID *)(SpdmRequest + 1);
      printf ("\n    VerifyData(");
      DumpData (VerifyData, HmacSize);
      printf (")");
    }
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  SpdmAppendMessageF (mCurrentSessionInfo, Buffer, MessageSize);
}

VOID
DumpSpdmPskFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                       MessageSize;
  UINT8                       TH2HashData[64];
  SPDM_DATA_PARAMETER         Parameter;
  BOOLEAN                     UsePsk;

  printf ("SPDM_PSK_FINISH_RSP ");

  MessageSize = sizeof(SPDM_PSK_FINISH_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  if (mCurrentSessionInfo == NULL) {
    return ;
  }
  SpdmAppendMessageF (mCurrentSessionInfo, Buffer, MessageSize);

  DEBUG ((DEBUG_INFO, "SpdmGenerateSessionDataKey[%x]\n", mCurrentSessionId));
  if (SpdmDumpSessionDataProvision (mSpdmContext, mCurrentSessionId, TRUE, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  if (SpdmDumpSessionDataCheck (mSpdmContext, mCurrentSessionId, TRUE) != RETURN_SUCCESS) {
    return ;
  }
  SpdmCalculateTH2Hash (mSpdmContext, mCurrentSessionInfo, TRUE, TH2HashData);
  SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), FALSE);

  UsePsk = FALSE;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
  SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

  SpdmGenerateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TH2HashData);

  UsePsk = TRUE;
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationSession;
  *(UINT32 *)Parameter.AdditionalData = mCurrentSessionId;
  SpdmSetData (mSpdmContext, SpdmDataSessionUsePsk, &Parameter, &UsePsk, sizeof(UsePsk));

  SpdmSecuredMessageSetUsePsk (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), TRUE);
  SpdmSecuredMessageSetSessionState (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmSessionStateEstablished);
}

VOID
DumpSpdmHeartbeat (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT ");

  if (BufferSize < sizeof(SPDM_HEARTBEAT_REQUEST)) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");
}

VOID
DumpSpdmHeartbeatAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT_ACK ");

  if (BufferSize < sizeof(SPDM_HEARTBEAT_RESPONSE)) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");
}

VOID
DumpSpdmKeyUpdate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_UPDATE_REQUEST  *SpdmRequest;

  printf ("SPDM_KEY_UPDATE ");

  if (BufferSize < sizeof(SPDM_KEY_UPDATE_REQUEST)) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    printf ("(KeyOp=0x%02x(", SpdmRequest->Header.Param1);
    DumpEntryValue (mSpdmKeyUpdateOperationStringTable, ARRAY_SIZE(mSpdmKeyUpdateOperationStringTable), SpdmRequest->Header.Param1);
    printf ("), Tag=0x%02x) ", SpdmRequest->Header.Param2);
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  if (mEncapsulated) {
    ASSERT (mCurrentSessionInfo != NULL);
    switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      SpdmCreateUpdateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmKeyUpdateActionResponder);
      break;
    }
  } else {
    switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      SpdmCreateUpdateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmKeyUpdateActionRequester);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
      SpdmCreateUpdateSessionDataKey (SpdmGetSecuredMessageContextViaSessionInfo (mCurrentSessionInfo), SpdmKeyUpdateActionAll);
      break;
    }
  }
}

VOID
DumpSpdmKeyUpdateAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_UPDATE_RESPONSE  *SpdmResponse;

  printf ("SPDM_KEY_UPDATE_ACK ");

  if (BufferSize < sizeof(SPDM_KEY_UPDATE_RESPONSE)) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(KeyOp=0x%02x(", SpdmResponse->Header.Param1);
    DumpEntryValue (mSpdmKeyUpdateOperationStringTable, ARRAY_SIZE(mSpdmKeyUpdateOperationStringTable), SpdmResponse->Header.Param1);
    printf ("), Tag=0x%02x) ", SpdmResponse->Header.Param2);
  }

  printf ("\n");
}

VOID
DumpSpdmGetEncapsulatedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_GET_ENCAPSULATED_REQUEST ");

  if (BufferSize < sizeof(SPDM_GET_ENCAPSULATED_REQUEST_REQUEST)) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");
}

VOID
DumpSpdmEncapsulatedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_ENCAPSULATED_REQUEST_RESPONSE  *SpdmResponse;
  UINTN                               HeaderSize;

  printf ("SPDM_ENCAPSULATED_REQUEST ");

  HeaderSize = sizeof(SPDM_ENCAPSULATED_REQUEST_RESPONSE);
  if (BufferSize < HeaderSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  if (!mParamQuiteMode) {
    printf ("(ReqID=0x%02x) ", SpdmResponse->Header.Param1);
  }

  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
  mEncapsulated = FALSE;
}

VOID
DumpSpdmDeliverEncapsulatedResponse (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST  *SpdmRequest;
  UINTN                                       HeaderSize;

  printf ("SPDM_DELIVER_ENCAPSULATED_RESPONSE ");

  HeaderSize = sizeof(SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST);
  if (BufferSize < HeaderSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  if (!mParamQuiteMode) {
    printf ("(ReqID=0x%02x) ", SpdmRequest->Header.Param1);
  }

  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
  mEncapsulated = FALSE;
}

VOID
DumpSpdmEncapsulatedResponseAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE  *SpdmResponse;
  UINTN                                    HeaderSize;

  printf ("SPDM_ENCAPSULATED_RESPONSE_ACK ");

  HeaderSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE);
  if (BufferSize < HeaderSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  if (!mParamQuiteMode) {
    printf ("(ReqID=0x%02x) ", SpdmResponse->Header.Param1);
  }

  switch (SpdmResponse->Header.Param2) {
  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
    if (!mParamQuiteMode) {
      printf ("(Done) ");
    }
    break;

  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
    mEncapsulated = TRUE;
    DumpSpdmMessage ((UINT8 *)Buffer + HeaderSize, BufferSize - HeaderSize);
    mEncapsulated = FALSE;
    return ;

  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER:
    if (BufferSize < HeaderSize + 1) {
      printf ("\n");
      return ;
    }

    if (!mParamQuiteMode) {
      printf ("(ReqSlotID=0x%02x) ", *((UINT8 *)Buffer + HeaderSize));
    }
    break;
  }
  printf ("\n");
}

VOID
DumpSpdmEndSession (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_END_SESSION_REQUEST  *SpdmRequest;

  printf ("SPDM_END_SESSION ");

  if (BufferSize < sizeof(SPDM_END_SESSION_REQUEST)) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Attr=0x%02x(", SpdmRequest->Header.Param1);
    DumpEntryFlags (mSpdmEndSessionAttributeStringTable, ARRAY_SIZE(mSpdmEndSessionAttributeStringTable), SpdmRequest->Header.Param1);
    printf (")) ");
  }

  printf ("\n");
}

VOID
DumpSpdmEndSessionAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_END_SESSION_ACK ");

  if (BufferSize < sizeof(SPDM_END_SESSION_RESPONSE)) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  SpdmFreeSessionId (mSpdmContext, mCurrentSessionId);

  printf ("\n");
}

DISPATCH_TABLE_ENTRY mSpdmDispatch[] = {
  {SPDM_DIGESTS,                       "SPDM_DIGESTS",                       DumpSpdmDigests},
  {SPDM_CERTIFICATE,                   "SPDM_CERTIFICATE",                   DumpSpdmCertificate},
  {SPDM_CHALLENGE_AUTH,                "SPDM_CHALLENGE_AUTH",                DumpSpdmChallengeAuth},
  {SPDM_VERSION,                       "SPDM_VERSION",                       DumpSpdmVersion},
  {SPDM_MEASUREMENTS,                  "SPDM_MEASUREMENTS",                  DumpSpdmMeasurements},
  {SPDM_CAPABILITIES,                  "SPDM_CAPABILITIES",                  DumpSpdmCapabilities},
  {SPDM_ALGORITHMS,                    "SPDM_ALGORITHMS",                    DumpSpdmAlgorithms},
  {SPDM_VENDOR_DEFINED_RESPONSE,       "SPDM_VENDOR_DEFINED_RESPONSE",       DumpSpdmVendorDefinedResponse},
  {SPDM_ERROR,                         "SPDM_ERROR",                         DumpSpdmError},
  {SPDM_KEY_EXCHANGE_RSP,              "SPDM_KEY_EXCHANGE_RSP",              DumpSpdmKeyExchangeRsp},
  {SPDM_FINISH_RSP,                    "SPDM_FINISH_RSP",                    DumpSpdmFinishRsp},
  {SPDM_PSK_EXCHANGE_RSP,              "SPDM_PSK_EXCHANGE_RSP",              DumpSpdmPskExchangeRsp},
  {SPDM_PSK_FINISH_RSP,                "SPDM_PSK_FINISH_RSP",                DumpSpdmPskFinishRsp},
  {SPDM_HEARTBEAT_ACK,                 "SPDM_HEARTBEAT_ACK",                 DumpSpdmHeartbeatAck},
  {SPDM_KEY_UPDATE_ACK,                "SPDM_KEY_UPDATE_ACK",                DumpSpdmKeyUpdateAck},
  {SPDM_ENCAPSULATED_REQUEST,          "SPDM_ENCAPSULATED_REQUEST",          DumpSpdmEncapsulatedRequest},
  {SPDM_ENCAPSULATED_RESPONSE_ACK,     "SPDM_ENCAPSULATED_RESPONSE_ACK",     DumpSpdmEncapsulatedResponseAck},
  {SPDM_END_SESSION_ACK,               "SPDM_END_SESSION_ACK",               DumpSpdmEndSessionAck},

  {SPDM_GET_DIGESTS,                   "SPDM_GET_DIGESTS",                   DumpSpdmGetDigests},
  {SPDM_GET_CERTIFICATE,               "SPDM_GET_CERTIFICATE",               DumpSpdmGetCertificate},
  {SPDM_CHALLENGE,                     "SPDM_CHALLENGE",                     DumpSpdmChallenge},
  {SPDM_GET_VERSION,                   "SPDM_GET_VERSION",                   DumpSpdmGetVersion},
  {SPDM_GET_MEASUREMENTS,              "SPDM_GET_MEASUREMENTS",              DumpSpdmGetMeasurements},
  {SPDM_GET_CAPABILITIES,              "SPDM_GET_CAPABILITIES",              DumpSpdmGetCapabilities},
  {SPDM_NEGOTIATE_ALGORITHMS,          "SPDM_NEGOTIATE_ALGORITHMS",          DumpSpdmNegotiateAlgorithms},
  {SPDM_VENDOR_DEFINED_REQUEST,        "SPDM_VENDOR_DEFINED_REQUEST",        DumpSpdmVendorDefinedRequest},
  {SPDM_RESPOND_IF_READY,              "SPDM_RESPOND_IF_READY",              DumpSpdmRespondIfReady},
  {SPDM_KEY_EXCHANGE,                  "SPDM_KEY_EXCHANGE",                  DumpSpdmKeyExchange},
  {SPDM_FINISH,                        "SPDM_FINISH",                        DumpSpdmFinish},
  {SPDM_PSK_EXCHANGE,                  "SPDM_PSK_EXCHANGE",                  DumpSpdmPskExchange},
  {SPDM_PSK_FINISH,                    "SPDM_PSK_FINISH",                    DumpSpdmPskFinish},
  {SPDM_HEARTBEAT,                     "SPDM_HEARTBEAT",                     DumpSpdmHeartbeat},
  {SPDM_KEY_UPDATE,                    "SPDM_KEY_UPDATE",                    DumpSpdmKeyUpdate},
  {SPDM_GET_ENCAPSULATED_REQUEST,      "SPDM_GET_ENCAPSULATED_REQUEST",      DumpSpdmGetEncapsulatedRequest},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE, "SPDM_DELIVER_ENCAPSULATED_RESPONSE", DumpSpdmDeliverEncapsulatedResponse},
  {SPDM_END_SESSION,                   "SPDM_END_SESSION",                   DumpSpdmEndSession},
};

VOID
DumpSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_MESSAGE_HEADER  *SpdmHeader;

  if (BufferSize < sizeof(SPDM_MESSAGE_HEADER)) {
    printf ("\n");
    return ;
  }

  SpdmHeader = Buffer;

  if (!mEncapsulated && !mDecrypted) {
    if ((SpdmHeader->RequestResponseCode & 0x80) != 0) {
      printf ("REQ->RSP ");
    } else {
      printf ("RSP->REQ ");
    }
  }
  printf ("SPDM(%x, 0x%02x) ", SpdmHeader->SPDMVersion, SpdmHeader->RequestResponseCode);

  DumpDispatchMessage (mSpdmDispatch, ARRAY_SIZE(mSpdmDispatch), SpdmHeader->RequestResponseCode, (UINT8 *)Buffer, BufferSize);

  if (mParamDumpHex) {
    if (!mEncapsulated) {
      printf ("  SPDM Message:\n");
    } else {
      printf ("  Encapsulated SPDM Message:\n");
    }
    DumpHex (Buffer, BufferSize);
  }
}

BOOLEAN
InitSpdmDump (
  VOID
  )
{
  SPDM_DATA_PARAMETER                            Parameter;

  mSpdmDecMessageBuffer = (VOID *)malloc (GetMaxPacketLength());
  if (mSpdmDecMessageBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  mSpdmLastMessageBuffer = (VOID *)malloc (GetMaxPacketLength());
  if (mSpdmLastMessageBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  mSpdmCertChainBuffer = (VOID *)malloc (MAX_SPDM_CERT_CHAIN_SIZE);
  if (mSpdmCertChainBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  mLocalUsedCertChainBuffer = (VOID *)malloc (MAX_SPDM_CERT_CHAIN_SIZE);
  if (mLocalUsedCertChainBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  mPeerCertChainBuffer = (VOID *)malloc (MAX_SPDM_CERT_CHAIN_SIZE);
  if (mPeerCertChainBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }

  mSpdmContext = (VOID *)malloc (SpdmGetContextSize());
  if (mSpdmContext == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  SpdmInitContext (mSpdmContext);

  //
  // Provision data in case the GET_CAPABILITIES or NEGOTIATE_ALGORITHMS are not sent.
  //
  ZeroMem (&Parameter, sizeof(Parameter));
  Parameter.Location = SpdmDataLocationLocal;
  SpdmSetData (mSpdmContext, SpdmDataCapabilityFlags, &Parameter, &mSpdmRequesterCapabilitiesFlags, sizeof(UINT32));
  Parameter.Location = SpdmDataLocationConnection;
  SpdmSetData (mSpdmContext, SpdmDataCapabilityFlags, &Parameter, &mSpdmResponderCapabilitiesFlags, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataMeasurementSpec, &Parameter, &mSpdmMeasurementSpec, sizeof(UINT8));
  SpdmSetData (mSpdmContext, SpdmDataMeasurementHashAlgo, &Parameter, &mSpdmMeasurementHashAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataBaseAsymAlgo, &Parameter, &mSpdmBaseAsymAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataBaseHashAlgo, &Parameter, &mSpdmBaseHashAlgo, sizeof(UINT32));
  SpdmSetData (mSpdmContext, SpdmDataDHENamedGroup, &Parameter, &mSpdmDHENamedGroup, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataAEADCipherSuite, &Parameter, &mSpdmAEADCipherSuite, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataReqBaseAsymAlg, &Parameter, &mSpdmReqBaseAsymAlg, sizeof(UINT16));
  SpdmSetData (mSpdmContext, SpdmDataKeySchedule, &Parameter, &mSpdmKeySchedule, sizeof(UINT16));

  return TRUE;

Error:
  if (mSpdmDecMessageBuffer != NULL) {
    free (mSpdmDecMessageBuffer);
    mSpdmDecMessageBuffer = NULL;
  }
  if (mSpdmLastMessageBuffer != NULL) {
    free (mSpdmLastMessageBuffer);
    mSpdmLastMessageBuffer = NULL;
  }
  if (mSpdmCertChainBuffer != NULL) {
    free (mSpdmCertChainBuffer);
    mSpdmCertChainBuffer = NULL;
  }
  if (mLocalUsedCertChainBuffer == NULL) {
    free (mLocalUsedCertChainBuffer);
    mLocalUsedCertChainBuffer = NULL;
  }
  if (mPeerCertChainBuffer == NULL) {
    free (mPeerCertChainBuffer);
    mPeerCertChainBuffer = NULL;
  }
  if (mSpdmContext != NULL) {
    free (mSpdmContext);
    mSpdmContext = NULL;
  }
  return FALSE;
}

VOID
DeinitSpdmDump (
  VOID
  )
{
  free (mSpdmDecMessageBuffer);
  free (mSpdmLastMessageBuffer);
  free (mSpdmCertChainBuffer);
  free (mLocalUsedCertChainBuffer);
  free (mPeerCertChainBuffer);
  free (mSpdmContext);
}