/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

void
PrintUsage (
  void
  )
{
  printf ("SpdmDump -r <PcapFileName>\n");
}

void
ProcessArgs (
  int argc,
  char *argv[ ]
  )
{
  BOOLEAN  Result;

  if (argc >= 2) {
    if ((strcmp (argv[1], "-h") == 0) ||
        (strcmp (argv[1], "--help") == 0)) {
      PrintUsage ();
      exit (0);
    }
    if (strcmp (argv[1], "-r") == 0) {
      if (argc == 3) {
        Result = OpenPcapPacketFile (argv[2]);
        if (!Result) {
          exit (0);
        }
      } else {
        PrintUsage ();
        exit (0);
      }
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