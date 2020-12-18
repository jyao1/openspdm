/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

BOOLEAN  mParamQuiteMode;
BOOLEAN  mParamAllMode;
BOOLEAN  mParamDumpAsn1;
BOOLEAN  mParamDumpVendorApp;
BOOLEAN  mParamDumpHex;

void
PrintUsage (
  void
  )
{
  printf ("%s -r <PcapFileName>\n", "SpdmDump");
  printf ("   [-q] (quite mode, dump message type only)\n");
  printf ("   [-a] (all mode, dump all fields) -- TBD\n");
  printf ("   [-n] (dump ASN.1 certificate) -- TBD\n");
  printf ("   [-d] (dump application message) -- TBD\n");
  printf ("   [-x] (dump message in hex)\n");
  printf ("   [--psk <pre-shared key>]\n");
  printf ("   [--dhe_secret <session DHE secret>]\n");
  printf ("   [--req_cert_chain <requester public cert chain file>]\n");
  printf ("   [--rsp_cert_chain <responder public cert chain file>]\n");
  printf ("\n");
  printf ("NOTE:\n");
  printf ("   [--psk] is required to decrypt a PSK session\n");
  printf ("   [--dhe_secret] is required to decrypt a non-PSK session\n");
  printf ("      Format: A hex string, whose count of char must be even.\n");
  printf ("              It must not have prefix '0x'. The leading '0' must be included.\n");
  printf ("              '0123CDEF' means 4 bytes 0x01, 0x23, 0xCD, 0xEF,\n");
  printf ("              where 0x01 is the first byte and 0xEF is the last byte in memory\n");
  printf ("\n");
  printf ("   [--req_cert_chain] is required to if GET_CERTIFICATE is not sent\n");
  printf ("   [--rsp_cert_chain] is required to if encapsulated GET_CERTIFICATE is not sent\n");
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

    if (strcmp (argv[0], "-n") == 0) {
      mParamDumpAsn1 = TRUE;
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

    if (strcmp (argv[0], "--req_cert_chain") == 0) {
      if (argc >= 2) {
        if (!ReadInputFile (argv[1], &mRequesterCertChainBuffer, &mRequesterCertChainBufferSize)) {
          printf ("invalid --req_cert_chain\n");
          PrintUsage ();
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
        if (!ReadInputFile (argv[1], &mResponderCertChainBuffer, &mResponderCertChainBufferSize)) {
          printf ("invalid --rsp_cert_chain\n");
          PrintUsage ();
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
  return 0;
}