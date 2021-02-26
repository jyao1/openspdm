/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmEmu.h"

/*
  EXE_MODE_SHUTDOWN
  EXE_MODE_CONTINUE
*/
UINT32  mExeMode = EXE_MODE_SHUTDOWN;

UINT32  mExeConnection = (0 |
                          // EXE_CONNECTION_VERSION_ONLY |
                          EXE_CONNECTION_DIGEST |
                          EXE_CONNECTION_CERT |
                          EXE_CONNECTION_CHAL |
                          EXE_CONNECTION_MEAS |
                          0);

UINT32  mExeSession = (0 |
                       EXE_SESSION_KEY_EX |
                       EXE_SESSION_PSK |
                       // EXE_SESSION_NO_END |
                       EXE_SESSION_KEY_UPDATE |
                       EXE_SESSION_HEARTBEAT |
                       EXE_SESSION_MEAS |
                       0);

VOID
PrintUsage (
  IN CHAR8* Name
  )
{
  printf ("\n%s [--trans MCTP|PCI_DOE]\n", Name);
  printf ("   [--ver 1.0|1.1]\n");
  printf ("   [--sec_ver 0|1.1]\n");
  printf ("   [--cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]\n");
  printf ("   [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--meas_spec DMTF]\n");
  printf ("   [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]\n");
  printf ("   [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]\n");
  printf ("   [--key_schedule HMAC_HASH]\n");
  printf ("   [--basic_mut_auth NO|BASIC]\n");
  printf ("   [--mut_auth NO|WO_ENCAP|W_ENCAP|DIGESTS]\n");
  printf ("   [--meas_sum NO|TCB|ALL]\n");
  printf ("   [--meas_op ONE_BY_ONE|ALL]\n");
  printf ("   [--key_upd REQ|ALL|RSP]\n");
  printf ("   [--slot <0~7|0xFF>]\n");
  printf ("   [--slot_count <1~8>]\n");
  printf ("   [--save_state <NegotiateStateFileName>]\n");
  printf ("   [--load_state <NegotiateStateFileName>]\n");
  printf ("   [--exe_mode SHUTDOWN|CONTINUE]\n");
  printf ("   [--exe_conn VER_ONLY|DIGEST|CERT|CHAL|MEAS]\n");
  printf ("   [--exe_session KEY_EX|PSK|NO_END|KEY_UPDATE|HEARTBEAT|MEAS]\n");
  printf ("   [--pcap <PcapFileName>]\n");
  printf ("\n");
  printf ("NOTE:\n");
  printf ("   [--trans] is used to select transport layer message. By default, MCTP is used.\n");
  printf ("   [--ver] is version. By default, 1.1 is used.\n");
  printf ("   [--sec_ver] is secured message version. By default, 1.1 is used. 0 means no secured message version negotiation.\n");
  printf ("   [--cap] is capability flags. Multiple flags can be set together. Please use ',' for them.\n");
  printf ("           By default, CERT,CHAL,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Requester.\n");
  printf ("           By default, CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK_WITH_CONTEXT,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Responder.\n");
  printf ("   [--hash] is hash algorithm. By default, SHA_384,SHA_256 is used.\n");
  printf ("   [--meas_spec] is measurement hash spec. By default, DMTF is used.\n");
  printf ("   [--meas_hash] is measurement hash algorithm. By default, SHA_512,SHA_384,SHA_256 is used.\n");
  printf ("   [--asym] is asym algorithm. By default, ECDSA_P384,ECDSA_P256 is used.\n");
  printf ("   [--req_asym] is requester asym algorithm. By default, RSAPSS_3072,RSAPSS_2048,RSASSA_3072,RSASSA_2048 is used.\n");
  printf ("   [--dhe] is DHE algorithm. By default, SECP_384_R1,SECP_256_R1,FFDHE_3072,FFDHE_2048 is used.\n");
  printf ("   [--aead] is AEAD algorithm. By default, AES_256_GCM,CHACHA20_POLY1305 is used.\n");
  printf ("   [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.\n");
  printf ("           Above algorithms also support multiple flags. Please use ',' for them.\n");
  printf ("           SHA3 is not supported so far.\n");
  printf ("   [--basic_mut_auth] is the basic mutual authentication policy. BASIC is used in CHALLENGE_AUTH. By default, BASIC is used.\n");
  printf ("   [--mut_auth] is the mutual authentication policy. WO_ENCAP, W_ENCAP or DIGESTS is used in KEY_EXCHANGE_RSP. By default, W_ENCAP is used.\n");
  printf ("   [--meas_sum] is the measurment summary hash type in CHALLENGE_AUTH, KEY_EXCHANGE_RSP and PSK_EXCHANGE_RSP. By default, ALL is used.\n");
  printf ("   [--meas_op] is the measurement operation in GET_MEASUREMEMT. By default, ONE_BY_ONE is used.\n");
  printf ("   [--key_upd] is the key update operation in KEY_UPDATE. By default, ALL is used. RSP will trigger encapsulated KEY_UPDATE.\n");
  printf ("   [--slot_id] is to select the peer slot ID in GET_MEASUREMENT, CHALLENGE_AUTH, KEY_EXCHANGE and FINISH. By default, 0 is used.\n");
  printf ("           0xFF can be used to indicate provisioned certificate chain. No GET_CERTIFICATE is needed.\n");
  printf ("           0xFF must be used to if PUB_KEY_ID is set. No GET_DIGEST/GET_CERTIFICATE is sent.\n");
  printf ("   [--slot_count] is to select the local slot count. By default, 3 is used.\n");
  printf ("   [--save_state] is to save the current negotiated state to a write-only file.\n");
  printf ("           The requester and responder will save state after GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.\n");
  printf ("           (negotiated state == ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule)\n");
  printf ("           The responder should set CACHE capabilities, otherwise the state will not be saved.\n");
  printf ("           The requester will clear PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION to preserve, otherwise this bit is set.\n");
  printf ("           The responder will save empty state, if the requester sets PRESERVE_NEGOTIATED_STATE_CLEAR bit in END_SESSION.\n");
  printf ("   [--load_state] is to load the negotiated state to current session from a read-only file.\n");
  printf ("           The requester and responder will provision the state just after SPDM context is created.\n");
  printf ("           The user need guarantee the state file is gnerated correctly.\n");
  printf ("           The command line input - ver|cap|hash|meas_spec|meas_hash|asym|req_asym|dhe|aead|key_schedule are ignored.\n");
  printf ("           The requester will skip GET_VERSION/GET_CAPABILLITIES/NEGOTIATE_ALGORITHMS.\n");
  printf ("   [--exe_mode] is used to control the execution mode. By default, it is SHUTDOWN.\n");
  printf ("           SHUTDOWN means the requester asks the responder to stop.\n");
  printf ("           CONTINUE means the requester asks the responder to preserve the current SPDM context.\n");
  printf ("   [--exe_conn] is used to control the SPDM connection. By default, it is DIGEST,CERT,CHAL,MEAS.\n");
  printf ("           VER_ONLY means REQUESTER does not send GET_CAPABILITIES/NEGOTIATE_ALGORITHMS. It is used for quick symmetric authentication with PSK.\n");
  printf ("           DIGEST means send GET_DIGESTS command.\n");
  printf ("           CERT means send GET_CERTIFICATE command.\n");
  printf ("           CHAL means send CHALLENGE command.\n");
  printf ("           MEAS means send GET_MEASUREMENT command.\n");
  printf ("   [--exe_session] is used to control the SPDM session. By default, it is KEY_EX,PSK,KEY_UPDATE,HEARTBEAT,MEAS.\n");
  printf ("           KEY_EX means to setup KEY_EXCHANGE session.\n");
  printf ("           PSK means to setup PSK_EXCHANGE session.\n");
  printf ("           NO_END means to not send END_SESSION.\n");
  printf ("           KEY_UPDATE means to send KEY_UPDATE in session.\n");
  printf ("           HEARTBEAT means to send HEARTBEAT in session.\n");
  printf ("           MEAS means send GET_MEASUREMENT command in session.\n");
  printf ("   [--pcap] is used to generate PCAP dump file for offline analysis.\n");
}

typedef struct {
  UINT32  Value;
  CHAR8   *Name;
} VALUE_STRING_ENTRY;

VALUE_STRING_ENTRY  mTransportValueStringTable[] = {
  {SOCKET_TRANSPORT_TYPE_MCTP,    "MCTP"},
  {SOCKET_TRANSPORT_TYPE_PCI_DOE, "PCI_DOE"},
};

VALUE_STRING_ENTRY  mVersionValueStringTable[] = {
  {SPDM_MESSAGE_VERSION_10,  "1.0"},
  {SPDM_MESSAGE_VERSION_11,  "1.1"},
};

VALUE_STRING_ENTRY  mSecuredMessageVersionValueStringTable[] = {
  {0,                        "0"},
  {SPDM_MESSAGE_VERSION_11,  "1.1"},
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

VALUE_STRING_ENTRY  mHashValueStringTable[] = {
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};

VALUE_STRING_ENTRY  mMeasurementSpecValueStringTable[] = {
  {SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF,        "DMTF"},
};

VALUE_STRING_ENTRY  mMeasurementHashValueStringTable[] = {
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,  "RAW_BIT"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,      "SHA_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,      "SHA_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,      "SHA_512"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,     "SHA3_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,     "SHA3_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,     "SHA3_512"},
};

VALUE_STRING_ENTRY  mAsymValueStringTable[] = {
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

VALUE_STRING_ENTRY  mDheValueStringTable[] = {
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,  "FFDHE_2048"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,  "FFDHE_3072"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,  "FFDHE_4096"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1"},
  {SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1"},
};

VALUE_STRING_ENTRY  mAeadValueStringTable[] = {
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,        "AES_128_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,        "AES_256_GCM"},
  {SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,  "CHACHA20_POLY1305"},
};

VALUE_STRING_ENTRY  mKeyScheduleValueStringTable[] = {
  {SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,        "HMAC_HASH"},
};

VALUE_STRING_ENTRY  mBasicMutAuthPolicyStringTable[] = {
  {0,                                                                "NO"},
  {1,                                                                "BASIC"},
};

VALUE_STRING_ENTRY  mMutAuthPolicyStringTable[] = {
  {0,                                                                "NO"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED,                    "WO_ENCAP"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST, "W_ENCAP"},
  {SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,   "DIGESTS"},
};

VALUE_STRING_ENTRY  mMeasurementSummaryHashTypeStringTable[] = {
  {SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,    "NO"},
  {SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, "TCB"},
  {SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH,          "ALL"},
};

VALUE_STRING_ENTRY  mMeasurementOperationStringTable[] = {
  {SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS, "ONE_BY_ONE"},
  {SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS,              "ALL"},
};

VALUE_STRING_ENTRY  mKeyUpdateActionStringTable[] = {
  {SpdmKeyUpdateActionRequester,  "REQ"},
  {SpdmKeyUpdateActionResponder,  "RSP"},
  {SpdmKeyUpdateActionAll,        "ALL"},
};

VALUE_STRING_ENTRY  mSlotIdStringTable[] = {
  {0x0, "0"},
  {0x1, "1"},
  {0x2, "2"},
  {0x3, "3"},
  {0x4, "4"},
  {0x5, "5"},
  {0x6, "6"},
  {0x7, "7"},
  {0xFF, "0xFF"},
};

VALUE_STRING_ENTRY  mSlotCountStringTable[] = {
  {0x1, "1"},
  {0x2, "2"},
  {0x3, "3"},
  {0x4, "4"},
  {0x5, "5"},
  {0x6, "6"},
  {0x7, "7"},
  {0x8, "8"},
};

VALUE_STRING_ENTRY  mExeModeStringTable[] = {
  {EXE_MODE_SHUTDOWN, "SHUTDOWN"},
  {EXE_MODE_CONTINUE, "CONTINUE"},
};

VALUE_STRING_ENTRY  mExeConnectionStringTable[] = {
  {EXE_CONNECTION_VERSION_ONLY,    "VER_ONLY"},
  {EXE_CONNECTION_DIGEST,          "DIGEST"},
  {EXE_CONNECTION_CERT,            "CERT"},
  {EXE_CONNECTION_CHAL,            "CHAL"},
  {EXE_CONNECTION_MEAS,            "MEAS"},
};

VALUE_STRING_ENTRY  mExeSessionStringTable[] = {
  {EXE_SESSION_KEY_EX,     "KEY_EX"},
  {EXE_SESSION_PSK,        "PSK"},
  {EXE_SESSION_NO_END,     "NO_END"},
  {EXE_SESSION_KEY_UPDATE, "KEY_UPDATE"},
  {EXE_SESSION_HEARTBEAT,  "HEARTBEAT"},
  {EXE_SESSION_MEAS,       "MEAS"},
};

BOOLEAN
GetValueFromName (
  IN VALUE_STRING_ENTRY  *Table,
  IN UINTN               EntryCount,
  IN CHAR8               *Name,
  OUT UINT32             *Value
  )
{
  UINTN  Index;

  for (Index = 0; Index < EntryCount; Index++) {
    if (strcmp (Name, Table[Index].Name) == 0) {
      *Value = Table[Index].Value;
      return TRUE;
    }
  }
  return FALSE;
}

BOOLEAN
GetFlagsFromName (
  IN VALUE_STRING_ENTRY  *Table,
  IN UINTN               EntryCount,
  IN CHAR8               *Name,
  OUT UINT32             *Flags
  )
{
  UINT32  Value;
  CHAR8   *FlagName;
  CHAR8   *LocalName;
  BOOLEAN Ret;

  LocalName = (VOID *)malloc (strlen(Name) + 1);
  if (LocalName == NULL) {
    return FALSE;
  }
  strcpy (LocalName, Name);

  //
  // Name = Flag1,Flag2,...,FlagN
  //
  *Flags = 0;
  FlagName = strtok (LocalName, ",");
  while (FlagName != NULL) {
    if (!GetValueFromName (Table, EntryCount, FlagName, &Value)) {
      printf ("unsupported flag - %s\n", FlagName);
      Ret = FALSE;
      goto Done;
    }
    *Flags |= Value;
    FlagName = strtok (NULL, ",");
  }
  if (*Flags == 0) {
    Ret = FALSE;
  } else {
    Ret = TRUE;
  }
Done:
  free (LocalName);
  return Ret;
}

void
ProcessArgs (
  char  *ProgramName,
  int   argc,
  char  *argv[ ]
  )
{
  UINT32  Data32;
  CHAR8   *PcapFileName;

  PcapFileName = NULL;

  if (argc == 1) {
    return ;
  }

  argc --;
  argv ++;

  if ((strcmp (argv[0], "-h") == 0) ||
      (strcmp (argv[0], "--help") == 0)) {
    PrintUsage (ProgramName);
    exit (0);
  }

  while (argc > 0) {
    if (strcmp (argv[0], "--trans") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mTransportValueStringTable, ARRAY_SIZE(mTransportValueStringTable), argv[1], &mUseTransportLayer)) {
          printf ("invalid --trans %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("trans - 0x%x\n", mUseTransportLayer);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --trans\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--ver") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mVersionValueStringTable, ARRAY_SIZE(mVersionValueStringTable), argv[1], &Data32)) {
          printf ("invalid --ver %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseVersion = (UINT8)Data32;
        printf ("ver - 0x%02x\n", mUseVersion);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --ver\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--sec_ver") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSecuredMessageVersionValueStringTable, ARRAY_SIZE(mSecuredMessageVersionValueStringTable), argv[1], &Data32)) {
          printf ("invalid --sec_ver %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseSecuredMessageVersion = (UINT8)Data32;
        printf ("sec_ver - 0x%02x\n", mUseSecuredMessageVersion);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --sec_ver\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--cap") == 0) {
      if (argc >= 2) {
        VALUE_STRING_ENTRY  *CapabilitiesStringTable;
        UINTN               Count;

        if (strcmp (ProgramName, "SpdmRequesterEmu") == 0) {
          CapabilitiesStringTable = mSpdmRequesterCapabilitiesStringTable;
          Count = ARRAY_SIZE(mSpdmRequesterCapabilitiesStringTable);
        } else if (strcmp (ProgramName, "SpdmResponderEmu") == 0) {
          CapabilitiesStringTable = mSpdmResponderCapabilitiesStringTable;
          Count = ARRAY_SIZE(mSpdmResponderCapabilitiesStringTable);
        } else {
          ASSERT (FALSE);
          printf ("unsupported --cap\n");
          PrintUsage (ProgramName);
          exit (0);
        }
        if (!GetFlagsFromName (CapabilitiesStringTable, Count, argv[1], &mUseCapabilityFlags)) {
          printf ("invalid --cap %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("cap - 0x%08x\n", mUseCapabilityFlags);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --cap\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--hash") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mHashValueStringTable, ARRAY_SIZE(mHashValueStringTable), argv[1], &mSupportHashAlgo)) {
          printf ("invalid --hash %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("hash - 0x%08x\n", mSupportHashAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --hash\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_spec") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mMeasurementSpecValueStringTable, ARRAY_SIZE(mMeasurementSpecValueStringTable), argv[1], &Data32)) {
          printf ("invalid --meas_spec %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mSupportMeasurementSpec = (UINT8)Data32;
        printf ("meas_spec - 0x%02x\n", mSupportMeasurementSpec);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_spec\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_hash") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mMeasurementHashValueStringTable, ARRAY_SIZE(mMeasurementHashValueStringTable), argv[1], &mSupportMeasurementHashAlgo)) {
          printf ("invalid --meas_hash %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("meas_hash - 0x%08x\n", mSupportMeasurementHashAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_hash\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--asym") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mAsymValueStringTable, ARRAY_SIZE(mAsymValueStringTable), argv[1], &mSupportAsymAlgo)) {
          printf ("invalid --asym %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("asym - 0x%08x\n", mSupportAsymAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --asym\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--req_asym") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mAsymValueStringTable, ARRAY_SIZE(mAsymValueStringTable), argv[1], &Data32)) {
          printf ("invalid --req_asym %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mSupportReqAsymAlgo = (UINT16)Data32;
        printf ("req_asym - 0x%04x\n", mSupportReqAsymAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --req_asym\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--dhe") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mDheValueStringTable, ARRAY_SIZE(mDheValueStringTable), argv[1], &Data32)) {
          printf ("invalid --dhe %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mSupportDheAlgo = (UINT16)Data32;
        printf ("dhe - 0x%04x\n", mSupportDheAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --dhe\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--aead") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mAeadValueStringTable, ARRAY_SIZE(mAeadValueStringTable), argv[1], &Data32)) {
          printf ("invalid --aead %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mSupportAeadAlgo = (UINT16)Data32;
        printf ("aead - 0x%04x\n", mSupportAeadAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --aead\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--key_schedule") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mKeyScheduleValueStringTable, ARRAY_SIZE(mKeyScheduleValueStringTable), argv[1], &Data32)) {
          printf ("invalid --key_schedule %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mSupportKeyScheduleAlgo = (UINT16)Data32;
        printf ("key_schedule - 0x%04x\n", mSupportKeyScheduleAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_schedule\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--basic_mut_auth") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mBasicMutAuthPolicyStringTable, ARRAY_SIZE(mBasicMutAuthPolicyStringTable), argv[1], &Data32)) {
          printf ("invalid --basic_mut_auth %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseBasicMutAuth = (UINT8)Data32;
        printf ("basic_mut_auth - 0x%02x\n", mUseBasicMutAuth);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --basic_mut_auth\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--mut_auth") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mMutAuthPolicyStringTable, ARRAY_SIZE(mMutAuthPolicyStringTable), argv[1], &Data32)) {
          printf ("invalid --mut_auth %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseMutAuth = (UINT8)Data32;
        printf ("mut_auth - 0x%02x\n", mUseMutAuth);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --mut_auth\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_sum") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mMeasurementSummaryHashTypeStringTable, ARRAY_SIZE(mMeasurementSummaryHashTypeStringTable), argv[1], &Data32)) {
          printf ("invalid --meas_sum %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseMeasurementSummaryHashType = (UINT8)Data32;
        printf ("meas_sum - 0x%02x\n", mUseMeasurementSummaryHashType);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_sum\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_op") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mMeasurementOperationStringTable, ARRAY_SIZE(mMeasurementOperationStringTable), argv[1], &Data32)) {
          printf ("invalid --meas_op %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseMeasurementOperation = (UINT8)Data32;
        printf ("meas_op - 0x%02x\n", mUseMeasurementOperation);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_op\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--key_upd") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mKeyUpdateActionStringTable, ARRAY_SIZE(mKeyUpdateActionStringTable), argv[1], &Data32)) {
          printf ("invalid --key_upd %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseKeyUpdateAction = Data32;
        printf ("key_upd - 0x%08x\n", mUseKeyUpdateAction);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_upd\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--slot_id") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSlotIdStringTable, ARRAY_SIZE(mSlotIdStringTable), argv[1], &Data32)) {
          printf ("invalid --slot_id %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseSlotId = (UINT8)Data32;
        printf ("slot_id - 0x%02x\n", mUseSlotId);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --slot_id\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--slot_count") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSlotCountStringTable, ARRAY_SIZE(mSlotCountStringTable), argv[1], &Data32)) {
          printf ("invalid --slot_count %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseSlotCount = (UINT8)Data32;
        printf ("slot_count - 0x%02x\n", mUseSlotCount);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --slot_count\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--save_state") == 0) {
      if (argc >= 2) {
        mSaveStateFileName = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --save_state\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--load_state") == 0) {
      if (argc >= 2) {
        mLoadStateFileName = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --load_state\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_mode") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mExeModeStringTable, ARRAY_SIZE(mExeModeStringTable), argv[1], &mExeMode)) {
          printf ("invalid --exe_mode %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("exe_mode - 0x%08x\n", mExeMode);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_mode\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_conn") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mExeConnectionStringTable, ARRAY_SIZE(mExeConnectionStringTable), argv[1], &mExeConnection)) {
          printf ("invalid --exe_conn %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("exe_conn - 0x%08x\n", mExeConnection);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_conn\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--exe_session") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mExeSessionStringTable, ARRAY_SIZE(mExeSessionStringTable), argv[1], &mExeSession)) {
          printf ("invalid --exe_session %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        printf ("exe_session - 0x%08x\n", mExeSession);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --exe_session\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--pcap") == 0) {
      if (argc >= 2) {
        PcapFileName = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --pcap\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    printf ("invalid %s\n", argv[0]);
    PrintUsage (ProgramName);
    exit (0);
  }

  //
  // Open PCAP file as last option, after the user indicates transport type.
  //
  if (PcapFileName != NULL) {
    if (!OpenPcapPacketFile (PcapFileName)) {
      PrintUsage (ProgramName);
      exit (0);
    }
  }

  return ;
}
