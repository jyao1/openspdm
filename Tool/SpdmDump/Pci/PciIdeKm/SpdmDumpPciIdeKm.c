/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID
DumpPciIdeKmQuery (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_IDE_KM_QUERY  *Query;

  printf ("QUERY ");

  if (BufferSize < sizeof(PCI_IDE_KM_QUERY)) {
    printf ("\n");
    return ;
  }

  Query = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Port=0x%02x) ", Query->PortIndex);
  }

  printf ("\n");
}

VOID
DumpPciIdeKmQueryResp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_IDE_KM_QUERY_RESP  *QueryResp;

  printf ("QUERY_RESP ");

  if (BufferSize < sizeof(PCI_IDE_KM_QUERY_RESP)) {
    printf ("\n");
    return ;
  }

  QueryResp = Buffer;

  if (!mParamQuiteMode) {
    printf ("(Port=0x%02x, S%02xB%02xDF%02x, MaxPort=0x%02x) ",
      QueryResp->PortIndex,
      QueryResp->Segment,
      QueryResp->BusNum,
      QueryResp->DevFuncNum,
      QueryResp->MaxPortIndex
      );
  }

  printf ("\n");
}

VOID
DumpPciIdeKmKeyProgram (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("KEY_PROG ");
  printf ("\n");
}

VOID
DumpPciIdeKmKeyProgramAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("KP_ACK ");
  printf ("\n");
}

VOID
DumpPciIdeKmKeySetGo (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("K_SET_GO ");
  printf ("\n");
}

VOID
DumpPciIdeKmKeySetStop (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("K_SET_STOP ");
  printf ("\n");
}

VOID
DumpPciIdeKmKeySetGoStopAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("K_SET_GOSTOP_ACK ");
  printf ("\n");
}

DISPATCH_TABLE_ENTRY mPciIdeKmDispatch[] = {
  {PCI_IDE_KM_OBJECT_ID_QUERY,             "QUERY",             DumpPciIdeKmQuery},
  {PCI_IDE_KM_OBJECT_ID_QUERY_RESP,        "QUERY_RESP",        DumpPciIdeKmQueryResp},
  {PCI_IDE_KM_OBJECT_ID_KEY_PROG,          "KEY_PROG",          DumpPciIdeKmKeyProgram},
  {PCI_IDE_KM_OBJECT_ID_KP_ACK,            "KP_ACK",            DumpPciIdeKmKeyProgramAck},
  {PCI_IDE_KM_OBJECT_ID_K_SET_GO,          "K_SET_GO",          DumpPciIdeKmKeySetGo},
  {PCI_IDE_KM_OBJECT_ID_K_SET_STOP,        "K_SET_STOP",        DumpPciIdeKmKeySetStop},
  {PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK,  "K_SET_GOSTOP_ACK",  DumpPciIdeKmKeySetGoStopAck},
};

VOID
DumpPciIdeKmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  PCI_IDE_KM_HEADER  *PciIdeKmHeader;

  if (BufferSize < sizeof(PCI_IDE_KM_HEADER)) {
    printf ("\n");
    return ;
  }
  PciIdeKmHeader = Buffer;

  printf ("IDE_KM(0x%02x) ", PciIdeKmHeader->ObjectId);

  DumpDispatchMessage (mPciIdeKmDispatch, ARRAY_SIZE(mPciIdeKmDispatch), PciIdeKmHeader->ObjectId, (UINT8 *)Buffer, BufferSize);
}
