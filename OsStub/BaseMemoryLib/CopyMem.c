/** @file
  CopyMem() implementation.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Base.h"

/**
  Copies a source buffer to a destination buffer, and returns the destination buffer.

  This function copies Length bytes from SourceBuffer to DestinationBuffer, and returns
  DestinationBuffer.  The implementation must be reentrant, and it must handle the case
  where SourceBuffer overlaps DestinationBuffer.

  If Length is greater than (MAX_ADDRESS - DestinationBuffer + 1), then ASSERT().
  If Length is greater than (MAX_ADDRESS - SourceBuffer + 1), then ASSERT().

  @param  DestinationBuffer   A pointer to the destination buffer of the memory copy.
  @param  SourceBuffer        A pointer to the source buffer of the memory copy.
  @param  Length              The number of bytes to copy from SourceBuffer to DestinationBuffer.

  @return DestinationBuffer.

**/
VOID *
EFIAPI
CopyMem (
  OUT VOID       *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{
  volatile UINT8  *PointerDst;
  volatile UINT8  *PointerSrc;

  PointerDst = (UINT8 *)DestinationBuffer;
  PointerSrc = (UINT8 *)SourceBuffer;
  while (Length-- != 0) {
    *(PointerDst++) = *(PointerSrc++);
  }

  return DestinationBuffer;
}
