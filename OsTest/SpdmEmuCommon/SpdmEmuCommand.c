/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmEmu.h"

UINT32  mUseTransportLayer = SOCKET_TRANSPORT_TYPE_MCTP;

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
  printf ("\n");
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
  printf ("\n");

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
  printf ("\n");

  Result = ReadData32 (Socket, &TransportType);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Receive TransportType: ");
  TransportType = ntohl(TransportType);
  DumpData ((UINT8 *)&TransportType, sizeof(UINT32));
  printf ("\n");
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
  case SOCKET_SPDM_COMMAND_SHUTDOWN:
    ClosePcapPacketFile ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
      //
      // Append MCTP_HEADER for PCAP
      //
      MCTP_HEADER  MctpHeader;
      MctpHeader.HeaderVersion = 0;
      MctpHeader.DestinationId = 0;
      MctpHeader.SourceId = 0;
      MctpHeader.MessageTag = 0xC0;
      AppendPcapPacketData (&MctpHeader, sizeof(MctpHeader), ReceiveBuffer, BytesReceived);
    } else {
      AppendPcapPacketData (NULL, 0, ReceiveBuffer, BytesReceived);
    }
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
  printf ("\n");
  BytesToSend = htonl(BytesToSend);

  Result = WriteBytes (Socket, Buffer, BytesToSend);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit Buffer:\n    ");
  DumpData (Buffer, BytesToSend);
  printf ("\n");
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
  printf ("\n");

  Result = WriteData32 (Socket, mUseTransportLayer);
  if (!Result) {
    return Result;
  }
  printf ("Platform Port Transmit TransportType: ");
  TransportType = ntohl(mUseTransportLayer);
  DumpData ((UINT8 *)&TransportType, sizeof(UINT32));
  printf ("\n");

  Result = WriteMultipleBytes (Socket, SendBuffer, (UINT32)BytesToSend);
  if (!Result) {
    return Result;
  }

  switch (Command) {
  case SOCKET_SPDM_COMMAND_SHUTDOWN:
    ClosePcapPacketFile ();
    break;
  case SOCKET_SPDM_COMMAND_NORMAL:
    if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_MCTP) {
      //
      // Append MCTP_HEADER for PCAP
      //
      MCTP_HEADER  MctpHeader;
      MctpHeader.HeaderVersion = 0;
      MctpHeader.DestinationId = 0;
      MctpHeader.SourceId = 0;
      MctpHeader.MessageTag = 0xC0;
      AppendPcapPacketData (&MctpHeader, sizeof(MctpHeader), SendBuffer, BytesToSend);
    } else {
      AppendPcapPacketData (NULL, 0, SendBuffer, BytesToSend);
    }
    break;
  }

  return TRUE;
}
