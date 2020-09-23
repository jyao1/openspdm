/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmTest.h"

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
