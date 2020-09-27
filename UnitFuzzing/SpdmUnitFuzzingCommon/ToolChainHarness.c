/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#undef NULL
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include "ToolChainHarness.h"

#ifdef TEST_WITH_LIBFUZZER
#include <stdint.h>
#include <stddef.h>
#endif

#ifdef TEST_WITH_KLEE
#include <klee/klee.h>
#endif

BOOLEAN
InitTestBuffer (
  IN CHAR8  *FileName,
  IN UINTN  MaxBufferSize,
  IN VOID   **TestBuffer,
  OUT UINTN *BufferSize
  )
{
  VOID  *Buffer;
  FILE  *File;
  UINTN FileSize;
  UINTN BytesRead;

  // 1. Allocate buffer
  Buffer = malloc (MaxBufferSize);
  if (Buffer == NULL) {
    return FALSE;
  }

  // 2. Assign to TestBuffer and BufferSize
  *TestBuffer = Buffer;
  if (BufferSize != NULL) {
    *BufferSize = MaxBufferSize;
  }

  // 3. Initialize TestBuffer
#ifdef TEST_WITH_KLEE
  // 3.1 For test with KLEE: write symbolic values to TestBuffer
  klee_make_symbolic((UINT8 *)Buffer, MaxBufferSize, "Buffer");
  return TRUE;
#endif

  File = fopen(FileName, "rb");
  if (File == NULL) {
    fputs ("File error", stderr);
    free (Buffer);
    exit (1);
  }
  fseek(File, 0, SEEK_END);

  FileSize = ftell (File);
  rewind (File);

  FileSize = FileSize > MaxBufferSize ? MaxBufferSize : FileSize;
  BytesRead = fread((void *)Buffer, 1, FileSize, File);
  if (BytesRead != FileSize) {
    fputs ("File error",stderr);
    free (Buffer);
    exit (1);
  }
  fclose (File);

  if (BufferSize != NULL) {
    *BufferSize = FileSize;
  }
  return TRUE;
}

#ifdef TEST_WITH_LIBFUZZER
#ifdef  TEST_WITH_LIBFUZZERWIN
int LLVMFuzzerTestOneInput(const wint_t *Data, size_t Size)
#else
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
#endif
{
  VOID                   *TestBuffer;
  UINTN                  MaxBufferSize;

  // 1. Initialize TestBuffer
  MaxBufferSize = GetMaxBufferSize();
  TestBuffer = AllocateZeroPool (MaxBufferSize);
  if (TestBuffer == NULL) {
    return 0;
  }
  if (Size > MaxBufferSize) {
    Size = MaxBufferSize;
  }
  CopyMem (TestBuffer, Data, Size);
  // 2. Run test
  RunTestHarness(TestBuffer, Size);
  // 3. Clean up
  free (TestBuffer);
  return 0;
}
#else
int main(int argc, char **argv)
{
  BOOLEAN                Res;
  VOID                   *TestBuffer;
  UINTN                  TestBufferSize;
  CHAR8                  *FileName;

  if (argc <= 1) {
    printf ("error - missing input file\n");
    exit(1);
  }

  FileName = argv[1];

  // 1. Initialize TestBuffer
  Res = InitTestBuffer (FileName, GetMaxBufferSize(), &TestBuffer, &TestBufferSize);
  if (!Res) {
    printf ("error - fail to init test buffer\n");
    return 0;
  }
  // 2. Run test
  RunTestHarness (TestBuffer, TestBufferSize);
  // 3. Clean up
  free (TestBuffer);
  return 0;
}
#endif
