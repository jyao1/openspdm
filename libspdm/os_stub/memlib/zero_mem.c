/** @file
  zero_mem() implementation.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "base.h"

/**
  Fills a target buffer with zeros, and returns the target buffer.

  This function fills length bytes of buffer with zeros, and returns buffer.

  If length > 0 and buffer is NULL, then ASSERT().
  If length is greater than (MAX_ADDRESS - buffer + 1), then ASSERT().

  @param  buffer      The pointer to the target buffer to fill with zeros.
  @param  length      The number of bytes in buffer to fill with zeros.

  @return buffer.

**/
void *
zero_mem (
  OUT void  *buffer,
  IN uintn  length
  )
{
  volatile uint8  *Pointer;

  Pointer = (uint8 *)buffer;
  while (length-- != 0) {
    *(Pointer++) = 0;
  }

  return buffer;
}
