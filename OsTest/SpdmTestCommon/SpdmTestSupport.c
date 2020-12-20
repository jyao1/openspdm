/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmTest.h"

VOID
DumpHexStr (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  )
{
  UINTN Index;

  for (Index = 0; Index < BufferSize; Index++) {
    printf ("%02x", Buffer[Index]);
  }
  printf ("\n");
}

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  )
{
  UINTN Index;

  for (Index = 0; Index < BufferSize; Index++) {
    printf ("%02x ", Buffer[Index]);
  }
  printf ("\n");
}

VOID
DumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN   Index;
  UINTN   Count;
  UINTN   Left;

#define COLUME_SIZE  (16 * 2)

  Count = Size / COLUME_SIZE;
  Left  = Size % COLUME_SIZE;
  for (Index = 0; Index < Count; Index++) {
    printf ("%04x: ", (UINT32)(Index * COLUME_SIZE));
    DumpData (Data + Index * COLUME_SIZE, COLUME_SIZE);
    printf ("\n");
  }

  if (Left != 0) {
    printf ("%04x: ", (UINT32)(Index * COLUME_SIZE));
    DumpData (Data + Index * COLUME_SIZE, Left);
    printf ("\n");
  }
}

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT VOID    **FileData,
  OUT UINTN   *FileSize
  )
{
  FILE                        *FpIn;
  UINTN                       TempResult;

  if ((FpIn = fopen (FileName, "rb")) == NULL) {
    printf ("Unable to open file %s\n", FileName);
    *FileData = NULL;
    return FALSE;
  }

  fseek (FpIn, 0, SEEK_END);
  *FileSize = ftell (FpIn);
  
  *FileData = (VOID *) malloc (*FileSize);
  if (NULL == *FileData) {
    printf ("No sufficient memory to allocate %s\n", FileName);
    fclose (FpIn);
    return FALSE;
  }
    
  fseek (FpIn, 0, SEEK_SET);
  TempResult = fread (*FileData, 1, *FileSize, FpIn);
  if (TempResult != *FileSize) {
    printf ("Read input file error %s", FileName);
    free ((VOID *)*FileData);
    fclose (FpIn);
    return FALSE;
  }

  fclose (FpIn);

  return TRUE;
}

BOOLEAN
WriteOutputFile (
  IN CHAR8   *FileName,
  IN VOID    *FileData,
  IN UINTN   FileSize
  )
{
  FILE                        *FpOut;

  if ((FpOut = fopen (FileName, "w+b")) == NULL) {
    printf ("Unable to open file %s\n", FileName);
    return FALSE;
  }

  if ((fwrite (FileData, 1, FileSize, FpOut)) != FileSize) {
    printf ("Write output file error %s\n", FileName);
    fclose (FpOut);
    return FALSE;
  }

  fclose (FpOut);

  return TRUE;
}

VOID
PrintUsage (
  IN CHAR8* Name
  )
{
  printf ("%s [--trans MCTP|PCI_DOE]\n", Name);
  printf ("   [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--measurement_hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]\n");
  printf ("   [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]\n");
  printf ("   [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]\n");
  printf ("   [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]\n");
  printf ("   [--key_schedule HMAC_HASH]\n");
  printf ("   [--pcap <PcapFileName>]\n");
  printf ("\n");
  printf ("NOTE:\n");
  printf ("   [--trans] is used to select transport layer message. By default, MCTP is used.\n");
  printf ("\n");
  printf ("   [--hash] is hash algorithm. By default, SHA_256 is used.\n");
  printf ("   [--measurement_hash] is measurement hash algorithm. By default, SHA_256 is used.\n");
  printf ("   [--asym] is asym algorithm. By default, ECDSA_P256 is used.\n");
  printf ("   [--req_asym] is requester asym algorithm. By default, RSASSA_2048 is used.\n");
  printf ("   [--dhe] is DHE algorithm. By default, SECP_256_R1 is used.\n");
  printf ("   [--aead] is AEAD algorithm. By default, AES_256_GCM is used.\n");
  printf ("   [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.\n");
  printf ("\n");
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

VALUE_STRING_ENTRY  mHashValueStringTable[] = {
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
};

VALUE_STRING_ENTRY  mMeasurementHashValueStringTable[] = {
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,  "SHA_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,  "SHA_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,  "SHA_512"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
  {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
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
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --trans\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--hash") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mHashValueStringTable, ARRAY_SIZE(mHashValueStringTable), argv[1], &mUseHashAlgo)) {
          printf ("invalid --hash %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --hash\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--measurement_hash") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mMeasurementHashValueStringTable, ARRAY_SIZE(mMeasurementHashValueStringTable), argv[1], &mUseMeasurementHashAlgo)) {
          printf ("invalid --measurement_hash %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --measurement_hash\n");
        PrintUsage (ProgramName);
        exit (0);
      }
    }

    if (strcmp (argv[0], "--asym") == 0) {
      if (argc >= 2) {
        if (!GetValueFromName (mAsymValueStringTable, ARRAY_SIZE(mAsymValueStringTable), argv[1], &mUseAsymAlgo)) {
          printf ("invalid --asym %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
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
        if (!GetValueFromName (mAsymValueStringTable, ARRAY_SIZE(mAsymValueStringTable), argv[1], &Data32)) {
          printf ("invalid --req_asym %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseReqAsymAlgo = (UINT16)Data32;
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
        if (!GetValueFromName (mDheValueStringTable, ARRAY_SIZE(mDheValueStringTable), argv[1], &Data32)) {
          printf ("invalid --dhe %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseDheAlgo = (UINT16)Data32;
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
        if (!GetValueFromName (mAeadValueStringTable, ARRAY_SIZE(mAeadValueStringTable), argv[1], &Data32)) {
          printf ("invalid --aead %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseAeadAlgo = (UINT16)Data32;
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
        if (!GetValueFromName (mKeyScheduleValueStringTable, ARRAY_SIZE(mKeyScheduleValueStringTable), argv[1], &Data32)) {
          printf ("invalid --key_schedule %s\n", argv[1]);
          PrintUsage (ProgramName);
          exit (0);
        }
        mUseKeyScheduleAlgo = (UINT16)Data32;
        argc -= 2;
        argv += 2;
        continue;
      } else {
        printf ("invalid --key_schedule\n");
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
