/** @file

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _TOOLCHAIN_HARNESS_LIB_
#define _TOOLCHAIN_HARNESS_LIB_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void
run_test_harness (
  IN void  *test_buffer,
  IN uintn test_buffer_size
  );

uintn
get_max_buffer_size (
  void
  );

#endif