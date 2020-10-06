/** @file
  Intrinsic Memory Routines Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2010 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/BaseMemoryLib.h>

typedef UINTN  size_t;

#if defined(__GNUC__) || defined(__clang__)
  #define GLOBAL_USED __attribute__((used))
#else
  #define GLOBAL_USED
#endif

/* OpenSSL will use floating point support, and C compiler produces the _fltused
   symbol by default. Simply define this symbol here to satisfy the linker. */
int  GLOBAL_USED _fltused = 1;

/* Sets buffers to a specified character */
void * memset (void *dest, int ch, size_t count)
{
  //
  // NOTE: Here we use one base implementation for memset, instead of the direct
  //       optimized SetMem() wrapper. Because the IntrinsicLib has to be built
  //       without whole program optimization option, and there will be some
  //       potential register usage errors when calling other optimized codes.
  //

  //
  // Declare the local variables that actually move the data elements as
  // volatile to prevent the optimizer from replacing this function with
  // the intrinsic memset()
  //
  volatile UINT8  *Pointer;

  Pointer = (UINT8 *)dest;
  while (count-- != 0) {
    *(Pointer++) = (UINT8)ch;
  }

  return dest;
}

void *memmove( void* dest, const void* src, size_t count )
{
  CopyMem (dest, src, count);
  return dest;
}

/* Compare bytes in two buffers. */
int memcmp (const void *buf1, const void *buf2, size_t count)
{
  return (int)CompareMem(buf1, buf2, count);
}

INTN
AsciiStrCmp (
  IN      CONST CHAR8               *FirstString,
  IN      CONST CHAR8               *SecondString
  )
{
  while ((*FirstString != '\0') && (*FirstString == *SecondString)) {
    FirstString++;
    SecondString++;
  }

  return *FirstString - *SecondString;
}

int strcmp (const char *s1, const char *s2)
{
  return (int)AsciiStrCmp(s1, s2);
}

UINTN
AsciiStrLen (
  IN      CONST CHAR8               *String
  )
{
  UINTN                             Length;

  if (String == NULL) {
    return 0;
  }
  for (Length = 0; *String != '\0'; String++, Length++) {
  }
  return Length;
}

unsigned int strlen(char *s)
{
  return (unsigned int)AsciiStrLen (s);
}

CHAR8 *
AsciiStrStr (
  IN      CONST CHAR8               *String,
  IN      CONST CHAR8               *SearchString
  )
{
  CONST CHAR8 *FirstMatch;
  CONST CHAR8 *SearchStringTmp;

  if (*SearchString == '\0') {
    return (CHAR8 *) String;
  }

  while (*String != '\0') {
    SearchStringTmp = SearchString;
    FirstMatch = String;

    while ((*String == *SearchStringTmp)
            && (*String != '\0')) {
      String++;
      SearchStringTmp++;
    }

    if (*SearchStringTmp == '\0') {
      return (CHAR8 *) FirstMatch;
    }

    if (*String == '\0') {
      return NULL;
    }

    String = FirstMatch + 1;
  }

  return NULL;
}

char *strstr(char *str1, const char *str2)
{
  return AsciiStrStr (str1, str2);
}
