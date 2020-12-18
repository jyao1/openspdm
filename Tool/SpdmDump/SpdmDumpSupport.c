/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

/**
  This function dump raw data.

  @param  Data  raw data
  @param  Size  raw data size
**/
VOID
DumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; Index++) {
    printf ("%02x ", Data[Index]);
  }
  printf ("\n");
}

/**
  This function dump raw data with colume format.

  @param  Data  raw data
  @param  Size  raw data size
**/
VOID
DumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINT32  Index;
  UINTN   Count;
  UINTN   Left;

#define COLUME_SIZE  (16 * 2)

  Count = Size / COLUME_SIZE;
  Left  = Size % COLUME_SIZE;
  for (Index = 0; Index < Count; Index++) {
    printf ("    %04x: ", Index * COLUME_SIZE);
    DumpData (Data + Index * COLUME_SIZE, COLUME_SIZE);
  }

  if (Left != 0) {
    printf ("    %04x: ", Index * COLUME_SIZE);
    DumpData (Data + Index * COLUME_SIZE, Left);
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
