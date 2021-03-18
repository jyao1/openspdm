/** @file

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <base.h>

void
debug_assert (
  IN const char8  *file_name,
  IN uintn        line_number,
  IN const char8  *description
  )
{
}

void
debug_print (
  IN  uintn        error_level,
  IN  const char8  *format,
  ...
  )
{
}
