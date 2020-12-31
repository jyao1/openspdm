/** @file
  SPDM common library.
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
InternalDumpHexStr (
  IN UINT8  *Data,
  IN UINTN  Size
  )
{
  UINTN  Index;
  for (Index = 0; Index < Size; Index++) {
    DEBUG ((DEBUG_INFO, "%02x", (UINTN)Data[Index]));
  }
}

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
  Reads a 24-bit value from memory that may be unaligned.

  @param  Buffer  The pointer to a 24-bit value that may be unaligned.

  @return The 24-bit value read from Buffer.
**/
UINT32
EFIAPI
SpdmReadUint24 (
  IN UINT8  *Buffer
  )
{
  return (UINT32)(Buffer[0] | Buffer[1] << 8 | Buffer[2] << 16);
}

/**
  Writes a 24-bit value to memory that may be unaligned.

  @param  Buffer  The pointer to a 24-bit value that may be unaligned.
  @param  Value   24-bit value to write to Buffer.

  @return The 24-bit value to write to Buffer.
**/
UINT32
EFIAPI
SpdmWriteUint24 (
  IN UINT8  *Buffer,
  IN UINT32 Value
  )
{
  Buffer[0] = (UINT8)(Value & 0xFF);
  Buffer[1] = (UINT8)((Value >> 8) & 0xFF);
  Buffer[2] = (UINT8)((Value >> 16) & 0xFF);
  return Value;
}

/**
  Append a new data buffer to the managed buffer.

  @param  ManagedBuffer                The managed buffer to be appended.
  @param  Buffer                       The address of the data buffer to be appended to the managed buffer.
  @param  BufferSize                   The size in bytes of the data buffer to be appended to the managed buffer.

  @retval RETURN_SUCCESS               The new data buffer is appended to the managed buffer.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be appended.
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
  if (Buffer == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != 0);
  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  ASSERT (ManagedBuffer->MaxBufferSize >= ManagedBuffer->BufferSize);
  if (BufferSize > ManagedBuffer->MaxBufferSize - ManagedBuffer->BufferSize) {
    // Do not ASSERT here, because command processor will append message from external.
    DEBUG ((DEBUG_ERROR, "AppendManagedBuffer 0x%x fail, rest 0x%x only\n", (UINT32)BufferSize, (UINT32)(ManagedBuffer->MaxBufferSize - ManagedBuffer->BufferSize)));
    return RETURN_BUFFER_TOO_SMALL;
  }
  ASSERT (BufferSize <= ManagedBuffer->MaxBufferSize - ManagedBuffer->BufferSize);

  CopyMem ((UINT8 *)(ManagedBuffer + 1) + ManagedBuffer->BufferSize, Buffer, BufferSize);
  ManagedBuffer->BufferSize += BufferSize;
  return RETURN_SUCCESS;
}

/**
  Shrink the size of the managed buffer.

  @param  ManagedBuffer                The managed buffer to be shrinked.
  @param  BufferSize                   The size in bytes of the size of the buffer to be shrinked.

  @retval RETURN_SUCCESS               The managed buffer is shrinked.
  @retval RETURN_BUFFER_TOO_SMALL      The managed buffer is too small to be shrinked.
**/
RETURN_STATUS
ShrinkManagedBuffer (
  IN OUT VOID            *MBuffer,
  IN UINTN               BufferSize
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  if (BufferSize == 0) {
    return RETURN_SUCCESS;
  }
  ASSERT (BufferSize != 0);
  ASSERT ((ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (ManagedBuffer->MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));
  ASSERT (ManagedBuffer->MaxBufferSize >= ManagedBuffer->BufferSize);
  if (BufferSize > ManagedBuffer->BufferSize) {
    return RETURN_BUFFER_TOO_SMALL;
  }
  ASSERT (BufferSize <= ManagedBuffer->BufferSize);

  ManagedBuffer->BufferSize -= BufferSize;
  return RETURN_SUCCESS;
}

/**
  Reset the managed buffer.
  The BufferSize is reset to 0.
  The MaxBufferSize is unchanged.
  The Buffer is not freed.

  @param  ManagedBuffer                The managed buffer to be shrinked.
**/
VOID
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
}

/**
  Return the size of managed buffer.

  @param  ManagedBuffer                The managed buffer.

  @return the size of managed buffer.
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
  Return the address of managed buffer.

  @param  ManagedBuffer                The managed buffer.

  @return the address of managed buffer.
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

/**
  Init the managed buffer.

  @param  ManagedBuffer                The managed buffer.
  @param  MaxBufferSize                The maximum size in bytes of the managed buffer.
**/
VOID
InitManagedBuffer (
  IN OUT VOID            *MBuffer,
  IN UINTN               MaxBufferSize
  )
{
  MANAGED_BUFFER  *ManagedBuffer;

  ManagedBuffer = MBuffer;

  ASSERT ((MaxBufferSize == MAX_SPDM_MESSAGE_BUFFER_SIZE) ||
          (MaxBufferSize == MAX_SPDM_MESSAGE_SMALL_BUFFER_SIZE));

  ManagedBuffer->MaxBufferSize = MaxBufferSize;
  ResetManagedBuffer (MBuffer);
}