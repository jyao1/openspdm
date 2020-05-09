/** @file
  C Run-Time Libraries (CRT) Wrapper Implementation for OpenSSL-based
  Cryptographic Library.

Copyright (c) 2009 - 2017, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <stdio.h>

int my_printf (const char *fmt, ...)
{
  ASSERT(FALSE);
  return 0;
}

int (*mbedtls_printf)( const char *format, ... ) = my_printf;

int my_snprintf(char *str, size_t size, const char *format, ...)
{
  ASSERT(FALSE);
  return 0;
}

int (*mbedtls_snprintf)( char * s, size_t n, const char * format, ... ) = my_snprintf;

void mbedtls_platform_zeroize( void *buf, size_t len )
{
    ZeroMem (buf, len);
}
