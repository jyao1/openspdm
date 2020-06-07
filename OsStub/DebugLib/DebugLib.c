/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

//
// Define the maximum debug and assert message length that this library supports
//
#define MAX_DEBUG_MESSAGE_LENGTH  0x100

#define DEBUG_ASSERT_NATIVE      0
#define DEBUG_ASSERT_DEADLOOP    1
#define DEBUG_ASSERT_BREAKPOINT  2

#define DEBUG_ASSERT_CHOICE      DEBUG_ASSERT_DEADLOOP

VOID
EFIAPI
DebugAssert (
  IN CONST CHAR8  *FileName,
  IN UINTN        LineNumber,
  IN CONST CHAR8  *Description
  )
{
  printf ("ASSERT: %s(%d): %s\n", FileName, (INT32)(UINT32)LineNumber, Description);

#if (DEBUG_ASSERT_CHOICE == DEBUG_ASSERT_DEADLOOP)
  {volatile INTN ___i = 1; while (___i);}
#elif (DEBUG_ASSERT_CHOICE == DEBUG_ASSERT_BREAKPOINT)
#if defined(_MSC_EXTENSIONS)
  __debugbreak();
#endif
#if defined(__GNUC__)
  __asm__ __volatile__("int $3");
#endif
#endif

  assert (FALSE);
}

VOID
EFIAPI
DebugPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  ...
  )
{
  CHAR8    Buffer[MAX_DEBUG_MESSAGE_LENGTH];
  va_list  Marker;
  
  va_start (Marker, Format);

  vsnprintf (Buffer, sizeof(Buffer), Format, Marker);

  va_end (Marker);

  printf ("%s", Buffer);
}
