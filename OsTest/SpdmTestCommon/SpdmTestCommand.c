/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmTest.h"

UINT32  mUseTransportLayer = SOCKET_TRANSPORT_TYPE_MCTP;

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  )
{
  UINTN Index;

  for (Index = 0; Index < BufferSize; Index++) {
    printf ("%02x ", Buffer[Index]);
  }
  printf ("\n");
}

/**
  Read number of bytes data in blocking mode.

  If there is no enough data in socket, this function will wait.
  This function will return if enough data is read, or socket error.
**/
BOOLEAN
ReadBytes (
  IN  SOCKET          Socket,
  OUT UINT8           *Buffer,
  IN  UINT32          NumberOfBytes
  )
{
  INT32                 Result;
  UINT32                NumberReceived;

  NumberReceived = 0;
  while (NumberReceived < NumberOfBytes) {
    Result = recv (Socket, (CHAR8 *)(Buffer + NumberReceived), NumberOfBytes - NumberReceived, 0);
    if (Result == -1) {
      printf ("Receive error - 0x%x\n",
#ifdef _MSC_VER
        WSAGetLastError()
#else
        errno
#endif
        );
      return FALSE;
    }
    if (Result == 0) {
      return FALSE;
    }
    NumberReceived += Result;
  }
  return TRUE;
}

BOOLEAN
ReadData32 (
  IN SOCKET           Socket,
  OUT UINT32          *Data
  )
{
  BOOLEAN  Result;

  Result = ReadBytes (Socket, (UINT8 *)Data, sizeof(UINT32));
  if (!Result) {
    return Result;
  }
  *Data = ntohl (*Data);
  return TRUE;
}

/**
  Read multiple bytes in blocking mode.

  The length is presented as first 4 bytes in big endian.
  The data follows the length.

  If there is no enough data in socket, this function will wait.
  This function will return if enough data is read, or socket error.
**/
BOOLEAN
ReadMultipleBytes (
  IN SOCKET           Socket,
  OUT UINT8           *Buffer,
  OUT UINT32          *BytesReceived,
  IN UINT32           MaxBufferLength
  )
{
  UINT32               Length;
  BOOLEAN              Result;

  Result = ReadData32 (Socket, &Length);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Receive Size: ");
  Length = ntohl(Length);
  DumpData ((UINT8 *)&Length, sizeof(UINT32));
  Length = ntohl(Length);

  *BytesReceived = Length;
  if (*BytesReceived > MaxBufferLength) {
    printf ("Buffer too small (0x%x). Expected - 0x%x\n", MaxBufferLength, *BytesReceived);
    return FALSE;
  }
  if (Length == 0) {
    return TRUE;
  }
  Result = ReadBytes (Socket, Buffer, Length);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Receive Buffer:\n    ");
  DumpData (Buffer, Length);

  return TRUE;
}

BOOLEAN
ReceivePlatformData (
  IN  SOCKET           Socket,
  OUT UINT32           *Command,
  OUT UINT8            *ReceiveBuffer,
  IN OUT UINTN         *BytesToReceive
  )
{
  BOOLEAN  Result;
  UINT32   Response;
  UINT32   TransportType;
  UINT32   BytesReceived;

  Result = ReadData32 (Socket, &Response);
  if (!Result) {
    return Result;
  }
  *Command = Response;
  printf ("Platform Port Receive Command: ");
  Response = ntohl(Response);
  DumpData ((UINT8 *)&Response, sizeof(UINT32));

  Result = ReadData32 (Socket, &TransportType);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Receive TransportType: ");
  TransportType = ntohl(TransportType);
  DumpData ((UINT8 *)&TransportType, sizeof(UINT32));
  TransportType = ntohl(TransportType);
  if (TransportType != mUseTransportLayer) {
    printf ("TransportType mismatch\n");
    return FALSE;
  }

  BytesReceived = 0;
  Result = ReadMultipleBytes (Socket, ReceiveBuffer, &BytesReceived, (UINT32)*BytesToReceive);
  if (!Result) {
    return Result;
  }
  *BytesToReceive = BytesReceived;

  switch (*Command) {
  case SOCKET_SPDM_COMMAND_STOP:
    ClosePcapPacketFile ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    AppendPcapPacketData (ReceiveBuffer, BytesReceived);
    break;
  }

  return Result;
}

/**
  Write number of bytes data in blocking mode.

  This function will return if data is written, or socket error.
**/
BOOLEAN
WriteBytes(
  IN  SOCKET           Socket,
  IN  UINT8            *Buffer,
  IN  UINT32           NumberOfBytes
  )
{
  INT32                Result;
  UINT32               NumberSent;

  NumberSent = 0;
  while (NumberSent < NumberOfBytes) {
    Result = send (Socket, (CHAR8 *)(Buffer + NumberSent), NumberOfBytes - NumberSent, 0);
    if (Result == -1) {
#ifdef _MSC_VER
      if (WSAGetLastError() == 0x2745) {
        printf ("Client disconnected\n");
      } else {
#endif
        printf ("Send error - 0x%x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
#ifdef _MSC_VER
      }
#endif
      return FALSE;
    }
    NumberSent += Result;
  }
  return TRUE;
}

BOOLEAN
WriteData32 (
  IN SOCKET           Socket,
  IN UINT32           Data
  )
{
  Data = htonl(Data);
  return WriteBytes (Socket, (UINT8 *)&Data, sizeof(UINT32));
}

/**
  Write multiple bytes.

  The length is presented as first 4 bytes in big endian.
  The data follows the length.
**/
BOOLEAN
WriteMultipleBytes (
  IN SOCKET           Socket,
  IN UINT8            *Buffer,
  IN UINT32           BytesToSend
  )
{
  BOOLEAN  Result;

  Result = WriteData32 (Socket, BytesToSend);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit Size: ");
  BytesToSend = htonl(BytesToSend);
  DumpData ((UINT8 *)&BytesToSend, sizeof(UINT32));
  BytesToSend = htonl(BytesToSend);

  Result = WriteBytes (Socket, Buffer, BytesToSend);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit Buffer:\n    ");
  DumpData (Buffer, BytesToSend);
  return TRUE;
}

BOOLEAN
SendPlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend
  )
{
  BOOLEAN  Result;
  UINT32   Request;
  UINT32   TransportType;

  Request = Command;
  Result = WriteData32 (Socket, Request);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit Command: ");
  Request = htonl(Request);
  DumpData ((UINT8 *)&Request, sizeof(UINT32));

  Result = WriteData32 (Socket, mUseTransportLayer);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit TransportType: ");
  TransportType = ntohl(mUseTransportLayer);
  DumpData ((UINT8 *)&TransportType, sizeof(UINT32));

  Result = WriteMultipleBytes (Socket, SendBuffer, (UINT32)BytesToSend);
  if (!Result) {
    return Result;
  }

  switch (Command) {
  case SOCKET_SPDM_COMMAND_STOP:
    ClosePcapPacketFile ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    AppendPcapPacketData (SendBuffer, BytesToSend);
    break;
  }

  return TRUE;
}
