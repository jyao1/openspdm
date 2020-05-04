/** @file
  EDKII Device Security library for SPDM device.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmCommonLibInternal.h"

/**

  This function dump raw data.

  @param  Data  raw data
  @param  Size  raw data size

**/
VOID
InternalDumpData (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN  Index;
  for (Index = 0; Index < Size; Index++) {
    DEBUG ((DEBUG_INFO, "%02x ", (UINTN)Data[Index]));
  }
}

/**

  This function dump raw data with colume format.

  @param  Data  raw data
  @param  Size  raw data size

**/
VOID
InternalDumpHex (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN   Index;
  UINTN   Count;
  UINTN   Left;

#define COLUME_SIZE  (16 * 2)

  Count = Size / COLUME_SIZE;
  Left  = Size % COLUME_SIZE;
  for (Index = 0; Index < Count; Index++) {
    DEBUG ((DEBUG_INFO, "%04x: ", Index * COLUME_SIZE));
    InternalDumpData (Data + Index * COLUME_SIZE, COLUME_SIZE);
    DEBUG ((DEBUG_INFO, "\n"));
  }

  if (Left != 0) {
    DEBUG ((DEBUG_INFO, "%04x: ", Index * COLUME_SIZE));
    InternalDumpData (Data + Index * COLUME_SIZE, Left);
    DEBUG ((DEBUG_INFO, "\n"));
  }
}

/**
  Append a new data buffer to the managed buffer.
**/
RETURN_STATUS
AppendManagedBuffer (
  IN OUT VOID            *MBuffer,
  IN VOID                *Buffer,
  IN UINTN               BufferSize
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  if (BufferSize == 0) {
    return RETURN_SUCCESS;
  }
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != 0);
  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  ASSERT (ManagedBuffer->MaxBufferSize >= ManagedBuffer->BufferSize);
  ASSERT (BufferSize <= ManagedBuffer->MaxBufferSize - ManagedBuffer->BufferSize);

  CopyMem ((UINT8 *)(ManagedBuffer + 1) + ManagedBuffer->BufferSize, Buffer, BufferSize);
  ManagedBuffer->BufferSize += BufferSize;
  return RETURN_SUCCESS;
}

/**
  Reset the managed buffer.
  The BufferSize is reset to 0.
  The MaxBufferSize is unchanged.
  The Buffer is not freed.
**/
RETURN_STATUS
ResetManagedBuffer (
  IN OUT VOID            *MBuffer
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  ManagedBuffer->BufferSize = 0;
  ZeroMem (ManagedBuffer + 1, ManagedBuffer->MaxBufferSize);
  return RETURN_SUCCESS;
}

/**
  Return the size of buffer
**/
UINTN
GetManagedBufferSize (
  IN OUT VOID            *MBuffer
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  return ManagedBuffer->BufferSize;
}

/**
  Return the buffer
**/
VOID *
GetManagedBuffer (
  IN OUT VOID            *MBuffer
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  return (ManagedBuffer + 1);
}
