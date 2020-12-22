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
UINT32             mCachedSessionId;
SPDM_SESSION_INFO  *mCurrentSessionInfo;
BOOLEAN            mEncapsulated;
BOOLEAN            mDecrypted;

VOID               *mSpdmCertChainBuffer;
UINTN              mSpdmCertChainBufferSize;
UINTN              mCachedSpdmCertChainBufferOffset;

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

DISPATCH_TABLE_ENTRY mSecuredSpdmDispatch[] = {
  {LINKTYPE_MCTP,    "", DumpMctpMessage},
  {LINKTYPE_PCI_DOE, "", DumpSpdmMessage},
};

VALUE_STRING_ENTRY  mSpdmRequesterCapabilitiesStringTable[] = {
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP,                   "CERT"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP,                   "CHAL"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_NO_SIG,            "MEAS_NO_SIG"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_CAP_SIG,               "MEAS_SIG"},
  {SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MEAS_FRESH_CAP,             "MEAS_FRESH"},
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

VALUE_STRING_ENTRY  mSpdmHashValueStringTable[] = {
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};

VALUE_STRING_ENTRY  mSpdmMeasurementHashValueStringTable[] = {
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};

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

VALUE_STRING_ENTRY  mSpdmDheValueStringTable[] = {
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,  "FFDHE_2048"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,  "FFDHE_3072"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,  "FFDHE_4096"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1"},
};

VALUE_STRING_ENTRY  mSpdmAeadValueStringTable[] = {
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,        "AES_128_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,        "AES_256_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,  "CHACHA20_POLY1305"},
};

VALUE_STRING_ENTRY  mSpdmKeyScheduleValueStringTable[] = {
  {SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,        "HMAC_HASH"},
};

VOID
DumpSpdmGetVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;
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

  SpdmContext = mSpdmContext;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
}

VOID
DumpSpdmVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT    *SpdmContext;
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

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
}

VOID
DumpSpdmGetCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT            *SpdmContext;
  UINTN                          MessageSize;
  SPDM_GET_CAPABILITIES_REQUEST  *SpdmRequest;

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
      printf ("(Flags=0x%08x) ", SpdmRequest->Flags);

      if (mParamAllMode) {
        printf ("\n    Flags(");
        DumpEntryFlags (mSpdmRequesterCapabilitiesStringTable, ARRAY_SIZE(mSpdmRequesterCapabilitiesStringTable), SpdmRequest->Flags);
        printf (") ");
      }
    } else {
      printf ("() ");
    }
  }

  printf ("\n");

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
}

VOID
DumpSpdmCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT         *SpdmContext;
  UINTN                       MessageSize;
  SPDM_CAPABILITIES_RESPONSE  *SpdmResponse;

  printf ("SPDM_CAPABILITIES ");

  MessageSize = sizeof(SPDM_CAPABILITIES_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Flags=0x%08x) ", SpdmResponse->Flags);

    if (mParamAllMode) {
      printf ("\n    Flags(");
      DumpEntryFlags (mSpdmResponderCapabilitiesStringTable, ARRAY_SIZE(mSpdmResponderCapabilitiesStringTable), SpdmResponse->Flags);
      printf (") ");
    }
  }

  printf ("\n");

  SpdmContext = mSpdmContext;
  SpdmContext->ConnectionInfo.Capability.Flags = ((SPDM_CAPABILITIES_RESPONSE *)Buffer)->Flags;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
}

VOID
DumpSpdmNegotiateAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT                            *SpdmContext;
  UINTN                                          MessageSize;
  SPDM_NEGOTIATE_ALGORITHMS_REQUEST              *SpdmRequest;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;

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
    printf ("(Hash=0x%08x, Asym=0x%08x",
      SpdmRequest->BaseHashAlgo,
      SpdmRequest->BaseAsymAlgo
      );

    if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      StructTable = (VOID *)((UINTN)Buffer +
                              sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                              SpdmRequest->ExtAsymCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                              SpdmRequest->ExtHashCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                              );
      for (Index = 0; Index <SpdmRequest->Header.Param1; Index++) {
        switch (StructTable[Index].AlgType) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
          printf (", DHE=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
          printf (", AEAD=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
          printf (", ReqAsym=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          printf (", KeySchedule=0x%04x", StructTable[Index].AlgSupported);
          break;
        }
      }
    }
    printf (") ");

    if (mParamAllMode) {
      printf ("\n    Hash(");
      DumpEntryFlags (mSpdmHashValueStringTable, ARRAY_SIZE(mSpdmHashValueStringTable), SpdmRequest->BaseHashAlgo);
      printf (") ");
      printf ("\n    Asym(");
      DumpEntryFlags (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), SpdmRequest->BaseAsymAlgo);
      printf (") ");

      if (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        StructTable = (VOID *)((UINTN)Buffer +
                                sizeof(SPDM_NEGOTIATE_ALGORITHMS_REQUEST) +
                                SpdmRequest->ExtAsymCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                                SpdmRequest->ExtHashCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                                );
        for (Index = 0; Index <SpdmRequest->Header.Param1; Index++) {
          switch (StructTable[Index].AlgType) {
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            printf ("\n    DHE(");
            DumpEntryFlags (mSpdmDheValueStringTable, ARRAY_SIZE(mSpdmDheValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            printf ("\n    AEAD(");
            DumpEntryFlags (mSpdmAeadValueStringTable, ARRAY_SIZE(mSpdmAeadValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            printf ("\n    ReqAsym(");
            DumpEntryFlags (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            printf ("\n    KeySchedule(");
            DumpEntryFlags (mSpdmKeyScheduleValueStringTable, ARRAY_SIZE(mSpdmKeyScheduleValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          }
        }
      }
    }

  }

  printf ("\n");

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
}

VOID
DumpSpdmAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT                            *SpdmContext;
  UINTN                                          MessageSize;
  SPDM_ALGORITHMS_RESPONSE                       *SpdmResponse;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;

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
    printf ("(Hash=0x%08x, MeasHash=0x%08x, Asym=0x%08x",
      SpdmResponse->BaseHashSel,
      SpdmResponse->MeasurementHashAlgo,
      SpdmResponse->BaseAsymSel
      );

    if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
      StructTable = (VOID *)((UINTN)Buffer +
                              sizeof(SPDM_ALGORITHMS_RESPONSE) +
                              SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                              SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                              );
      for (Index = 0; Index <SpdmResponse->Header.Param1; Index++) {
        switch (StructTable[Index].AlgType) {
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
          printf (", DHE=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
          printf (", AEAD=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
          printf (", ReqAsym=0x%04x", StructTable[Index].AlgSupported);
          break;
        case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
          printf (", KeySchedule=0x%04x", StructTable[Index].AlgSupported);
          break;
        }
      }
    }
    printf (") ");

    if (mParamAllMode) {
      printf ("\n    Hash(");
      DumpEntryValue (mSpdmHashValueStringTable, ARRAY_SIZE(mSpdmHashValueStringTable), SpdmResponse->BaseHashSel);
      printf (") ");
      printf ("\n    MeasHash(");
      DumpEntryValue (mSpdmMeasurementHashValueStringTable, ARRAY_SIZE(mSpdmMeasurementHashValueStringTable), SpdmResponse->MeasurementHashAlgo);
      printf (") ");
      printf ("\n    Asym(");
      DumpEntryValue (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), SpdmResponse->BaseAsymSel);
      printf (") ");

      if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        StructTable = (VOID *)((UINTN)Buffer +
                                sizeof(SPDM_ALGORITHMS_RESPONSE) +
                                SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                                SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                                );
        for (Index = 0; Index <SpdmResponse->Header.Param1; Index++) {
          switch (StructTable[Index].AlgType) {
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            printf ("\n    DHE(");
            DumpEntryValue (mSpdmDheValueStringTable, ARRAY_SIZE(mSpdmDheValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            printf ("\n    AEAD(");
            DumpEntryValue (mSpdmAeadValueStringTable, ARRAY_SIZE(mSpdmAeadValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            printf ("\n    ReqAsym(");
            DumpEntryValue (mSpdmAsymValueStringTable, ARRAY_SIZE(mSpdmAsymValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            printf ("\n    KeySchedule(");
            DumpEntryValue (mSpdmKeyScheduleValueStringTable, ARRAY_SIZE(mSpdmKeyScheduleValueStringTable), StructTable[Index].AlgSupported);
            printf (") ");
            break;
          }
        }
      }
    }

  }

  printf ("\n");

  SpdmContext = mSpdmContext;

  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = SpdmResponse->MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = SpdmResponse->BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = SpdmResponse->BaseHashSel;

  if (SpdmResponse->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    StructTable = (VOID *)((UINTN)Buffer +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            SpdmResponse->ExtAsymSelCount * sizeof(SPDM_EXTENDED_ALGORITHM) +
                            SpdmResponse->ExtHashSelCount * sizeof(SPDM_EXTENDED_ALGORITHM)
                            );
    for (Index = 0; Index <SpdmResponse->Header.Param1; Index++) {
      switch (StructTable[Index].AlgType) {
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
        SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = StructTable[Index].AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
        SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = StructTable[Index].AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
        SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = StructTable[Index].AlgSupported;
        break;
      case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
        SpdmContext->ConnectionInfo.Algorithm.KeySchedule = StructTable[Index].AlgSupported;
        break;
      }
    }
  }

  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, MessageSize);
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

  HashSize = GetSpdmHashSize (mSpdmContext);

  MessageSize += SlotCount * HashSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(SlotMask=0x%02x) ", SpdmResponse->Header.Param2);
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
    printf ("(SlotNum=0x%02x, Offset=0x%x, Length=0x%x) ",
      SpdmRequest->Header.Param1,
      SpdmRequest->Offset,
      SpdmRequest->Length
      );
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
    printf ("(SlotNum=0x%02x, PortLen=0x%x, RemLen=0x%x) ",
      SpdmResponse->Header.Param1,
      SpdmResponse->PortionLength,
      SpdmResponse->RemainderLength
      );
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

  if (SpdmResponse->RemainderLength == 0) {
    HashSize = GetSpdmHashSize (mSpdmContext);
    if (mSpdmCertChainBufferSize <= sizeof(SPDM_CERT_CHAIN) + HashSize) {
      printf ("\n");
      return ;
    }

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

  if (!mParamQuiteMode) {
    printf ("(SlotNUm=0x%02x, HashType=0x%02x) ",
      SpdmRequest->Header.Param1,
      SpdmRequest->Header.Param2
      );
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
  UINTN                         SignatureSize;
  UINT16                        OpaqueLength;

  printf ("SPDM_CHALLENGE_AUTH ");

  HashSize = GetSpdmHashSize (mSpdmContext);
  SignatureSize = GetSpdmAsymSize (mSpdmContext);

  MessageSize = sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + HashSize + 32 + HashSize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_CHALLENGE_AUTH_RESPONSE) + HashSize + 32 + HashSize);
  MessageSize += OpaqueLength + SignatureSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    printf ("(RspAttr=0x%02x (SlotNum=0x%02x, BasicMutAuthReq=%x), SlotMask=0x%02x) ",
      SpdmResponse->Header.Param1,
      SpdmResponse->Header.Param1 & 0xF,
      ((SpdmResponse->Header.Param1 & 0x80) != 0) ? 1 : 0,
      SpdmResponse->Header.Param2
      );
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
    if (IncludeSignature && (SpdmRequest->Header.SPDMVersion >= SPDM_MESSAGE_VERSION_11)) {
      printf ("(Attr=0x%02x, MeasOp=0x%02x, SlotId=0x%02x) ",
        SpdmRequest->Header.Param1,
        SpdmRequest->Header.Param2,
        SpdmRequest->SlotIDParam
        );
    } else {
      printf ("(Attr=0x%02x, MeasOp=0x%02x) ",
        SpdmRequest->Header.Param1,
        SpdmRequest->Header.Param2
        );
    }
  }

  printf ("\n");
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
    SignatureSize = GetSpdmAsymSize (mSpdmContext);

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
    if (mCachedGetMeasurementOperation == SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS) {
      if (IncludeSignature) {
        printf ("(SlotNum=0x%02x, TotalMeasIndex=0x%02x) ",
          SpdmResponse->Header.Param2,
          SpdmResponse->Header.Param1
          );
      } else {
        printf ("(TotalMeasIndex=0x%02x) ",
          SpdmResponse->Header.Param1
          );
      }
    } else {
      if (IncludeSignature) {
        printf ("(SlotNum=0x%02x, NumOfBlocks=0x%x, MeasRecordLen=0x%x) ",
          SpdmResponse->Header.Param2,
          SpdmResponse->NumberOfBlocks,
          MeasurementRecordLength
          );
      } else {
        printf ("(NumOfBlocks=0x%x, MeasRecordLen=0x%x) ",
          SpdmResponse->NumberOfBlocks,
          MeasurementRecordLength
          );
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
  printf ("SPDM_RESPOND_IF_READY ");
  printf ("\n");
}

VOID
DumpSpdmError (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_ERROR ");
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
  UINT16                     OpaqueDataLength;

  printf ("SPDM_KEY_EXCHANGE ");

  MessageSize = sizeof(SPDM_KEY_EXCHANGE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  DheKeySize = GetSpdmDheKeySize (mSpdmContext);
  MessageSize += DheKeySize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueDataLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_KEY_EXCHANGE_REQUEST) + DheKeySize);
  MessageSize += OpaqueDataLength;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(ReqSessionID=0x%04x) ", SpdmRequest->ReqSessionID);
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
  SPDM_DEVICE_CONTEXT         *SpdmContext;
  SPDM_KEY_EXCHANGE_RESPONSE  *SpdmResponse;
  UINTN                       MessageSize;
  UINTN                       DheKeySize;
  UINTN                       HashSize;
  UINTN                       SignatureSize;
  UINTN                       HmacSize;
  UINT16                      OpaqueDataLength;

  printf ("SPDM_KEY_EXCHANGE_RSP ");

  MessageSize = sizeof(SPDM_KEY_EXCHANGE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  SpdmContext = mSpdmContext;
  DheKeySize = GetSpdmDheKeySize (mSpdmContext);
  SignatureSize = GetSpdmAsymSize (mSpdmContext);
  HashSize = GetSpdmHashSize (mSpdmContext);
  HmacSize = GetSpdmHashSize (mSpdmContext);

  MessageSize += DheKeySize + HashSize + sizeof(UINT16);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  OpaqueDataLength = *(UINT16 *)((UINTN)Buffer + sizeof(SPDM_KEY_EXCHANGE_RESPONSE) + DheKeySize + HashSize);
  MessageSize += OpaqueDataLength + SignatureSize;
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    MessageSize += HmacSize;
  }
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(RspSessionID=0x%04x, MutAuth=0x%02x, SlotID=0x%02x) ",
      SpdmResponse->RspSessionID,
      SpdmResponse->MutAuthRequested,
      SpdmResponse->SlotIDParam
      );
  }

  printf ("\n");

  mCachedSessionId = mCachedSessionId | SpdmResponse->RspSessionID;
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId);
  ASSERT (mCurrentSessionInfo != NULL);
  mCurrentSessionInfo->UsePsk = FALSE;
  mCurrentSessionInfo->MutAuthRequested = SpdmResponse->MutAuthRequested;

  HmacSize = GetSpdmHashSize (mSpdmContext);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, MessageSize - HmacSize);
  } else {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, MessageSize);
  }
  SpdmCalculateSessionHandshakeKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + MessageSize - HmacSize, HmacSize);
  }

  mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
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

  printf ("SPDM_FINISH ");

  MessageSize = sizeof(SPDM_FINISH_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;
  SignatureSize = GetSpdmReqAsymSize (mSpdmContext);
  HmacSize = GetSpdmHashSize (mSpdmContext);

  if (SpdmRequest->Header.Param1 != 0) {
    MessageSize += SignatureSize;
  }
  MessageSize += HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(SigIncl=0x%02x, SlotNum=0x%02x) ",
      SpdmRequest->Header.Param1,
      SpdmRequest->Header.Param2
      );
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, MessageSize);
}

VOID
DumpSpdmFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                 MessageSize;
  UINTN                 HmacSize;

  printf ("SPDM_FINISH_RSP ");

  MessageSize = sizeof(SPDM_FINISH_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  HmacSize = GetSpdmHashSize (mSpdmContext);

  MessageSize += HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, MessageSize);

  SpdmCalculateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  mCurrentSessionInfo->SessionState = SpdmStateEstablished;
}

VOID
DumpSpdmPskExchange (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_PSK_EXCHANGE_REQUEST  *SpdmRequest;
  UINTN                      MessageSize;

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

  if (!mParamQuiteMode) {
    printf ("(ReqSessionID=0x%04x, PSKHint=", SpdmRequest->ReqSessionID);
    DumpHexStr ((VOID *)(SpdmRequest + 1), SpdmRequest->PSKHintLength);
    printf (") ");
  }

  printf ("\n");

  mCachedSessionId = (((SPDM_PSK_EXCHANGE_REQUEST *)Buffer)->ReqSessionID << 16);
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
  UINTN                       HashSize;
  UINTN                       HmacSize;

  printf ("SPDM_PSK_EXCHANGE_RSP ");

  MessageSize = sizeof(SPDM_PSK_EXCHANGE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;
  HashSize = GetSpdmHashSize (mSpdmContext);
  HmacSize = GetSpdmHashSize (mSpdmContext);
  MessageSize += HashSize + SpdmResponse->ResponderContextLength + SpdmResponse->OpaqueLength + HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("(RspSessionID=0x%04x) ", SpdmResponse->RspSessionID);
  }

  printf ("\n");

  mCachedSessionId = mCachedSessionId | SpdmResponse->RspSessionID;
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId);
  ASSERT (mCurrentSessionInfo != NULL);
  mCurrentSessionInfo->UsePsk = TRUE;

  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, MessageSize - HmacSize);
  SpdmCalculateSessionHandshakeKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + MessageSize - HmacSize, HmacSize);

  mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
}

VOID
DumpSpdmPskFinish (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                       MessageSize;
  UINTN                       HmacSize;

  printf ("SPDM_PSK_FINISH ");

  MessageSize = sizeof(SPDM_PSK_FINISH_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  HmacSize = GetSpdmHashSize (mSpdmContext);
  MessageSize += HmacSize;
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  if (!mParamQuiteMode) {
    printf ("() ");
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, MessageSize);
}

VOID
DumpSpdmPskFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                       MessageSize;

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
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, MessageSize);

  SpdmCalculateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  mCurrentSessionInfo->SessionState = SpdmStateEstablished;
}

VOID
DumpSpdmHeartbeat (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT ");
  printf ("\n");
}

VOID
DumpSpdmHeartbeatAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT_ACK ");
  printf ("\n");
}

VOID
DumpSpdmKeyUpdate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_UPDATE_REQUEST  *SpdmRequest;
  UINTN                    MessageSize;

  printf ("SPDM_KEY_UPDATE ");

  MessageSize = sizeof(SPDM_KEY_UPDATE_REQUEST);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmRequest = Buffer;

  if (!mParamQuiteMode) {
    switch (SpdmRequest->Header.Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      printf ("(UPDATE_KEY, Tag=0x%02x) ", SpdmRequest->Header.Param2);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
      printf ("(UPDATE_ALL_KEYS, Tag=0x%02x) ", SpdmRequest->Header.Param2);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
      printf ("(VERIFY_NEW_KEY, Tag=0x%02x) ", SpdmRequest->Header.Param2);
      break;
    }
  }

  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
    SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionRequester);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
    SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionAll);
    break;
  }
}

VOID
DumpSpdmKeyUpdateAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_KEY_UPDATE_RESPONSE  *SpdmResponse;
  UINTN                     MessageSize;

  printf ("SPDM_KEY_UPDATE_ACK ");

  MessageSize = sizeof(SPDM_KEY_UPDATE_RESPONSE);
  if (BufferSize < MessageSize) {
    printf ("\n");
    return ;
  }

  SpdmResponse = Buffer;

  if (!mParamQuiteMode) {
    switch (SpdmResponse->Header.Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      printf ("(UPDATE_KEY, Tag=0x%02x) ", SpdmResponse->Header.Param2);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
      printf ("(UPDATE_ALL_KEYS, Tag=0x%02x) ", SpdmResponse->Header.Param2);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
      printf ("(VERIFY_NEW_KEY, Tag=0x%02x) ", SpdmResponse->Header.Param2);
      break;
    }
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
  printf ("\n");
}

VOID
DumpSpdmEncapsulatedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_ENCAPSULATED_REQUEST_RESPONSE  *SpdmResponse;

  printf ("SPDM_ENCAPSULATED_REQUEST ");

  SpdmResponse = Buffer;
  if (!mParamQuiteMode) {
    printf ("(ReqID=0x%02x) ", SpdmResponse->Header.Param1);
  }

  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
  mEncapsulated = FALSE;
}

VOID
DumpSpdmDeliverEncapsulatedResponse (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DELIVER_ENCAPSULATED_RESPONSE_REQUEST  *SpdmRequest;

  printf ("SPDM_DELIVER_ENCAPSULATED_RESPONSE ");
  
  SpdmRequest = Buffer;
  if (!mParamQuiteMode) {
    printf ("(ReqID=0x%02x) ", SpdmRequest->Header.Param1);
  }

  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
  mEncapsulated = FALSE;
}

VOID
DumpSpdmEncapsulatedResponseAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE  *SpdmResponse;
  UINTN                                    MessageSize;

  printf ("SPDM_ENCAPSULATED_RESPONSE_ACK ");

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
    DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
    mEncapsulated = FALSE;
    return ;

  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER:
    MessageSize = sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE) + 1;
    if (BufferSize < MessageSize) {
      printf ("\n");
      return ;
    }

    if (!mParamQuiteMode) {
      printf ("(Slot(%d)) ", *((UINT8 *)Buffer + sizeof(SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE)));
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
  printf ("SPDM_END_SESSION ");
  printf ("\n");
}

VOID
DumpSpdmEndSessionAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_END_SESSION_ACK ");
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

VOID
DumpSecuredSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *SecuredMessageHeader;
  RETURN_STATUS                       Status;
  UINTN                               MessageSize;
  STATIC BOOLEAN                      IsRequester = FALSE;

  if (BufferSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER)) {
    printf ("\n");
    return ;
  }

  SecuredMessageHeader = Buffer;
  IsRequester = (BOOLEAN)(!IsRequester);

  MessageSize = GetMaxPacketLength();
  Status = SpdmDecodeSecuredMessage (
             mSpdmContext,
             SecuredMessageHeader->SessionId,
             IsRequester,
             BufferSize,
             Buffer,
             &MessageSize,
             mSpdmDecMessageBuffer
             );
  if (RETURN_ERROR(Status)) {
    //
    // Try other direction, because a responder might initiate a message in Session.
    //
    Status = SpdmDecodeSecuredMessage (
              mSpdmContext,
              SecuredMessageHeader->SessionId,
              !IsRequester,
              BufferSize,
              Buffer,
              &MessageSize,
              mSpdmDecMessageBuffer
              );
    if (!RETURN_ERROR(Status)) {
      IsRequester = !IsRequester;
    }
  }

  if (!RETURN_ERROR(Status)) {
    mCurrentSessionInfo = SpdmGetSessionInfoViaSessionId (mSpdmContext, SecuredMessageHeader->SessionId);

    if (IsRequester) {
      printf ("REQ->RSP ");
    } else {
      printf ("RSP->REQ ");
    }
    printf ("SecuredSPDM(0x%08x) ", SecuredMessageHeader->SessionId);

    mDecrypted = TRUE;
    DumpDispatchMessage (mSecuredSpdmDispatch, ARRAY_SIZE(mSecuredSpdmDispatch), GetDataLinkType(), mSpdmDecMessageBuffer, MessageSize);
    mDecrypted = FALSE;
  } else {
    printf ("(?)->(?) ");
    printf ("SecuredSPDM(0x%08x) ", SecuredMessageHeader->SessionId);
    printf ("<Unknown> ");
    printf ("\n");
  }

  if (mParamDumpHex) {
    printf ("  SecuredSPDM Message:\n");
    DumpHex (Buffer, BufferSize);
  }
}

BOOLEAN
InitSpdmDump (
  VOID
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

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

  mSpdmContext = (VOID *)malloc (SpdmGetContextSize());
  if (mSpdmContext == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  SpdmInitContext (mSpdmContext);

  SpdmContext = mSpdmContext;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = (VOID *)malloc (MAX_SPDM_CERT_CHAIN_SIZE);
  if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  
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
  if (mSpdmContext != NULL) {
    if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
      free (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer);
    }
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
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  free (mSpdmDecMessageBuffer);
  free (mSpdmLastMessageBuffer);
  free (mSpdmCertChainBuffer);

  SpdmContext = mSpdmContext;
  if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
    free (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer);
  }
  free (mSpdmContext);
}