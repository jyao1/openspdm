/** @file  

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Cryptest.h"

#include <stdio.h>

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
