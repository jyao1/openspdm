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
CHAR8    *mParamPsk;
CHAR8    *mParamReqDhePrivKey;
CHAR8    *mParamRspDhePrivKey;

void
PrintUsage (
  void
  )
{
  printf ("%s version 0.1\n", "SpdmDump");
  printf ("%s -r <PcapFileName>\n", "SpdmDump");
  printf ("   [-q] (quite mode, dump message type only)\n");
  printf ("   [-a] (all mode, dump all fields) -- TBD\n");
  printf ("   [-n] (dump ASN.1 certificate) -- TBD\n");
  printf ("   [-d] (dump application message) -- TBD\n");
  printf ("   [-x] (dump message in hex)\n");
  printf ("   [--psk <PSK>] -- TBD\n");
  printf ("   [--req_priv <requester DHE private key>] -- TBD\n");
  printf ("   [--rsp_priv <responder DHE private key>] -- TBD\n");
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
  ProcessArgs (argc, argv);

  DumpPcap ();

  ClosePcapPacketFile ();
  return 0;
}