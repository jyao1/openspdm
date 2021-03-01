/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

BOOLEAN  mParamQuiteMode;
BOOLEAN  mParamAllMode;
BOOLEAN  mParamDumpVendorApp;
BOOLEAN  mParamDumpHex;
CHAR8    *mParamOutRspCertChainFileName;
CHAR8    *mParamOutReqCertChainFileName;

extern UINT32             mSpdmRequesterCapabilitiesFlags;
extern UINT32             mSpdmResponderCapabilitiesFlags;
extern UINT8              mSpdmMeasurementSpec;
extern UINT32             mSpdmMeasurementHashAlgo;
extern UINT32             mSpdmBaseAsymAlgo;
extern UINT32             mSpdmBaseHashAlgo;
extern UINT16             mSpdmDHENamedGroup;
extern UINT16             mSpdmAEADCipherSuite;
extern UINT16             mSpdmReqBaseAsymAlg;
extern UINT16             mSpdmKeySchedule;

extern VALUE_STRING_ENTRY  mSpdmRequesterCapabilitiesStringTable[];
extern UINTN               mSpdmRequesterCapabilitiesStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmResponderCapabilitiesStringTable[];
extern UINTN               mSpdmResponderCapabilitiesStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmHashValueStringTable[];
extern UINTN               mSpdmHashValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmMeasurementHashValueStringTable[];
extern UINTN               mSpdmMeasurementHashValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmAsymValueStringTable[];
extern UINTN               mSpdmAsymValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmDheValueStringTable[];
extern UINTN               mSpdmDheValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmAeadValueStringTable[];
extern UINTN               mSpdmAeadValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmKeyScheduleValueStringTable[];
extern UINTN               mSpdmKeyScheduleValueStringTableCount;
extern VALUE_STRING_ENTRY  mSpdmMeasurementSpecValueStringTable[];
extern UINTN               mSpdmMeasurementSpecValueStringTableCount;

DISPATCH_TABLE_ENTRY *
GetDispatchEntryById (
  IN DISPATCH_TABLE_ENTRY  *DispatchTable,
  IN UINTN                 DispatchTableCount,
  IN UINT32                Id
  )
{
  UINTN  Index;

  for (Index = 0; Index < DispatchTableCount; Index++) {
    if (DispatchTable[Index].Id == Id) {
      return &DispatchTable[Index];
    }
  }
  return NULL;
}

VOID
DumpDispatchMessage (
  IN DISPATCH_TABLE_ENTRY  *DispatchTable,
  IN UINTN                 DispatchTableCount,
  IN UINT32                Id,
  IN VOID                  *Buffer,
  IN UINTN                 BufferSize
  )
{
  DISPATCH_TABLE_ENTRY *Entry;

  Entry = GetDispatchEntryById (DispatchTable, DispatchTableCount, Id);
  if (Entry != NULL) {
    if (Entry->DumpFunc != NULL) {
      Entry->DumpFunc (Buffer, BufferSize);
    } else if (Entry->Name != NULL) {
      printf ("%s\n", Entry->Name);
    }
  } else {
    printf ("<Unknown>\n");
  }
}

VOID
DumpEntryFlags (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Flags
  )
{
  UINTN   Index;
  BOOLEAN First;

  First = TRUE;
  for (Index = 0; Index < EntryTableCount; Index++) {
    if ((EntryTable[Index].Value & Flags) != 0) {
      if (First) {
        First = FALSE;
      } else {
        printf (",");
      }
      printf ("%s", EntryTable[Index].Name);
    }
  }
}

VOID
DumpEntryFlagsAll (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Flags
  )
{
  UINTN  Index;

  for (Index = 0; Index < EntryTableCount; Index++) {
    if (Index != 0) {
      printf (", ");
    }
    printf ("%s=%d",
      EntryTable[Index].Name,
      ((EntryTable[Index].Value & Flags) != 0) ? 1 : 0
      );
  }
}

VOID
DumpEntryValue (
  IN VALUE_STRING_ENTRY  *EntryTable,
  IN UINTN               EntryTableCount,
  IN UINT32              Value
  )
{
  UINTN  Index;

  for (Index = 0; Index < EntryTableCount; Index++) {
    if (EntryTable[Index].Value == Value) {
      printf ("%s", EntryTable[Index].Name);
      return ;
    }
  }
  printf ("<Unknown>");
}

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
PrintUsage (
  void
  )
{
  printf ("\n%s -r <PcapFileName>\n", "SpdmDump");
  printf ("   [-q] (quite mode, dump message type only)\n");
  printf ("   [-a] (all mode, dump all fields)\n");
  printf ("   [-d] (dump application message)\n");
  printf ("   [-x] (dump message in hex)\n");
  printf ("   [--psk <pre-shared key>]\n");
  printf ("   [--dhe_secret <session DHE secret>]\n");
  printf ("   [--req_cap       CERT|CHAL|                                ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|                 ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]\n");
  printf ("   [--rsp_cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]\n");
  printf ("   [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--meas_spec DMTF]\n");
  printf ("   [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]\n");
  printf ("   [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]\n");
  printf ("   [--key_schedule HMAC_HASH]\n");
  printf ("   [--req_cert_chain <input requester public cert chain file>]\n");
  printf ("   [--rsp_cert_chain <input responder public cert chain file>]\n");
  printf ("   [--out_req_cert_chain <output requester public cert chain file>]\n");
  printf ("   [--out_rsp_cert_chain <output responder public cert chain file>]\n");
  printf ("\n");
  printf ("NOTE:\n");
  printf ("   [--psk] is required to decrypt a PSK session\n");
  printf ("   [--dhe_secret] is required to decrypt a non-PSK session\n");
  printf ("      Format: A hex string, whose count of char must be even.\n");
  printf ("              It must not have prefix '0x'. The leading '0' must be included.\n");
  printf ("              '0123CDEF' means 4 bytes 0x01, 0x23, 0xCD, 0xEF,\n");
  printf ("              where 0x01 is the first byte and 0xEF is the last byte in memory\n");
  printf ("\n");
  printf ("   [--req_cap] and [--rsp_cap] means requester capability flags and responder capability flags.\n");
  printf ("      Format: Capabilities can be multiple flags. Please use ',' for them.\n");
  printf ("   [--hash], [--meas_spec], [--meas_hash], [--asym], [--req_asym], [--dhe], [--aead], [--key_schedule] means negotiated algorithms.\n");
  printf ("      Format: Algorithms must include only one flag.\n");
  printf ("      Capabilities and algorithms are required if GET_CAPABILITIES or NEGOTIATE_ALGORITHMS is not sent.\n");
  printf ("              For example, the negotiated state session or quick PSK session.\n");
  printf ("\n");
  printf ("   [--req_cert_chain] is required to if encapsulated GET_CERTIFICATE is not sent\n");
  printf ("   [--rsp_cert_chain] is required to if GET_CERTIFICATE is not sent\n");
  printf ("   [--out_req_cert_chain] can be used if encapsulated GET_CERTIFICATE is sent\n");
  printf ("   [--out_rsp_cert_chain] can be used if GET_CERTIFICATE is sent\n");
  printf ("      Format: A file containing certificates defined in SPDM spec 'certificate chain fomrat'.\n");
  printf ("              It is one or more ASN.1 DER-encoded X.509 v3 certificates.\n");
  printf ("              It may include multiple certificates, starting from root cert to leaf cert.\n");
  printf ("              It does not include the Length, Reserved, or RootHash fields.\n");
}

void
ProcessArgs (
  int   argc,
  char  *argv[ ]
  )
{
  CHAR8   *PcapFileName;
  UINT32  Data32;
  BOOLEAN Res;

  PcapFileName = NULL;

  if (argc == 1) {
    return ;
  }

  argc --;
  argv ++;

  if ((strcmp (argv[0], "-h") == 0) ||
      (strcmp (argv[0], "--help") == 0)) {
    PrintUsage ();
    exit (0);
  }

  while (argc > 0) {
    if (strcmp (argv[0], "-r") == 0) {
      if (argc >= 2) {
        PcapFileName = argv[1];
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid -r\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "-q") == 0) {
      mParamQuiteMode = TRUE;
      argc -= 1;
      argv += 1;
      continue;
    }

    if (strcmp (argv[0], "-a") == 0) {
      mParamAllMode = TRUE;
      argc -= 1;
      argv += 1;
      continue;
    }

    if (strcmp (argv[0], "-d") == 0) {
      mParamDumpVendorApp = TRUE;
      argc -= 1;
      argv += 1;
      continue;
    }

    if (strcmp (argv[0], "-x") == 0) {
      mParamDumpHex = TRUE;
      argc -= 1;
      argv += 1;
      continue;
    }

    if (strcmp (argv[0], "--psk") == 0) {
      if (argc >= 2) {
        if (!HexStringToBuffer (argv[1], &mPskBuffer, &mPskBufferSize)) {
          printf ("invalid --psk\n");
          PrintUsage ();
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --psk\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--dhe_secret") == 0) {
      if (argc >= 2) {
        if (!HexStringToBuffer (argv[1], &mDheSecretBuffer, &mDheSecretBufferSize)) {
          printf ("invalid --dhe_secret\n");
          PrintUsage ();
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --dhe_secret\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--req_cap") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mSpdmRequesterCapabilitiesStringTable, mSpdmRequesterCapabilitiesStringTableCount, argv[1], &mSpdmRequesterCapabilitiesFlags)) {
          printf ("invalid --req_cap %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        printf ("req_cap - 0x%08x\n", mSpdmRequesterCapabilitiesFlags);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --req_cap\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--rsp_cap") == 0) {
      if (argc >= 2) {
        if (!GetFlagsFromName (mSpdmResponderCapabilitiesStringTable, mSpdmResponderCapabilitiesStringTableCount, argv[1], &mSpdmResponderCapabilitiesFlags)) {
          printf ("invalid --rsp_cap %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        printf ("rsp_cap - 0x%08x\n", mSpdmResponderCapabilitiesFlags);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --rsp_cap\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--hash") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmHashValueStringTable, mSpdmHashValueStringTableCount, argv[1], &mSpdmBaseHashAlgo)) {
          printf ("invalid --hash %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        printf ("hash - 0x%08x\n", mSpdmBaseHashAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --hash\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_spec") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmMeasurementSpecValueStringTable, mSpdmMeasurementSpecValueStringTableCount, argv[1], &Data32)) {
          printf ("invalid --meas_spec %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        mSpdmMeasurementSpec = (UINT8)Data32;
        printf ("meas_spec - 0x%02x\n", mSpdmMeasurementSpec);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_spec\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--meas_hash") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmMeasurementHashValueStringTable, mSpdmMeasurementHashValueStringTableCount, argv[1], &mSpdmMeasurementHashAlgo)) {
          printf ("invalid --meas_hash %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        printf ("meas_hash - 0x%08x\n", mSpdmMeasurementHashAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --meas_hash\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--asym") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmAsymValueStringTable, mSpdmAsymValueStringTableCount, argv[1], &mSpdmBaseAsymAlgo)) {
          printf ("invalid --asym %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        printf ("asym - 0x%08x\n", mSpdmBaseAsymAlgo);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --asym\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--req_asym") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmAsymValueStringTable, mSpdmAsymValueStringTableCount, argv[1], &Data32)) {
          printf ("invalid --req_asym %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        mSpdmReqBaseAsymAlg = (UINT16)Data32;
        printf ("req_asym - 0x%04x\n", mSpdmReqBaseAsymAlg);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --req_asym\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--dhe") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmDheValueStringTable, mSpdmDheValueStringTableCount, argv[1], &Data32)) {
          printf ("invalid --dhe %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        mSpdmDHENamedGroup = (UINT16)Data32;
        printf ("dhe - 0x%04x\n", mSpdmDHENamedGroup);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --dhe\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--aead") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmAeadValueStringTable, mSpdmAeadValueStringTableCount, argv[1], &Data32)) {
          printf ("invalid --aead %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        mSpdmAEADCipherSuite = (UINT16)Data32;
        printf ("aead - 0x%04x\n", mSpdmAEADCipherSuite);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --aead\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--key_schedule") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mSpdmKeyScheduleValueStringTable, mSpdmKeyScheduleValueStringTableCount, argv[1], &Data32)) {
          printf ("invalid --key_schedule %s\n", argv[1]);
          PrintUsage ();
          exit (0);
        }
        mSpdmKeySchedule = (UINT16)Data32;
        printf ("key_schedule - 0x%04x\n", mSpdmKeySchedule);
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_schedule\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--req_cert_chain") == 0) {
      if (argc >= 2) {
        Res = ReadInputFile (argv[1], &mRequesterCertChainBuffer, &mRequesterCertChainBufferSize); 
        if (!Res) {
          printf ("invalid --req_cert_chain\n");
          PrintUsage ();
          exit (0);
        }
        if (mRequesterCertChainBufferSize > MAX_SPDM_CERT_CHAIN_SIZE) {
          printf ("req_cert_chain is too larger. Please increase MAX_SPDM_CERT_CHAIN_SIZE and rebuild.\n");
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --req_cert_chain\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--rsp_cert_chain") == 0) {
      if (argc >= 2) {
        Res = ReadInputFile (argv[1], &mResponderCertChainBuffer, &mResponderCertChainBufferSize);
        if (!Res) {
          printf ("invalid --rsp_cert_chain\n");
          PrintUsage ();
          exit (0);
        }
        if (mRequesterCertChainBufferSize > MAX_SPDM_CERT_CHAIN_SIZE) {
          printf ("rsp_cert_chain is too larger. Please increase MAX_SPDM_CERT_CHAIN_SIZE and rebuild.\n");
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --rsp_cert_chain\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--out_req_cert_chain") == 0) {
      if (argc >= 2) {
        mParamOutReqCertChainFileName = argv[1];
        if (!OpenOutputFile (mParamOutReqCertChainFileName)) {
          printf ("invalid --out_req_cert_chain\n");
          PrintUsage ();
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --out_req_cert_chain\n");
        PrintUsage ();
        exit (0);
      }
    }

    if (strcmp (argv[0], "--out_rsp_cert_chain") == 0) {
      if (argc >= 2) {
        mParamOutRspCertChainFileName = argv[1];
        if (!OpenOutputFile (mParamOutRspCertChainFileName)) {
          printf ("invalid --out_rsp_cert_chain\n");
          PrintUsage ();
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --out_rsp_cert_chain\n");
        PrintUsage ();
        exit (0);
      }
    }

    printf ("invalid %s\n", argv[0]);
    PrintUsage ();
    exit (0);
  }

  if (PcapFileName != NULL) {
    if (!OpenPcapPacketFile (PcapFileName)) {
      PrintUsage ();
      exit (0);
    }
  }
}

int main (
  int argc,
  char *argv[ ]
  )
{
  printf ("%s version 0.1\n", "SpdmDump");

  ProcessArgs (argc, argv);

  if (!InitSpdmDump ()) {
    ClosePcapPacketFile ();
    return 0;
  }

  DumpPcap ();

  DeinitSpdmDump ();

  ClosePcapPacketFile ();

  if (mRequesterCertChainBuffer != NULL) {
    free (mRequesterCertChainBuffer);
  }
  if (mResponderCertChainBuffer != NULL) {
    free (mResponderCertChainBuffer);
  }
  return 0;
}