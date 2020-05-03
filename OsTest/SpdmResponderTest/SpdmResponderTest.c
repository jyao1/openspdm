/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderTest.h"

UINT8  mReceiveBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

VOID
SpdmServerInit (
  VOID
  );

BOOLEAN
ProcessSpdmData (
  IN UINT32     Command,
  IN VOID       *RequestBuffer,
  IN UINTN      RequestBufferSize,
  OUT VOID      *ResponseBuffer,
  IN OUT UINTN  *ResponseBufferSize
  );

BOOLEAN
CreateSocket(
  IN  UINT16              PortNumber,
  IN  SOCKET              *ListenSocket
  )
{
  struct               sockaddr_in MyAddress;
  INT32                Res;
//  
    // Initialize Winsock
#ifdef _MSC_VER
  WSADATA              Ws;
  Res = WSAStartup(MAKEWORD(2, 2), &Ws);
  if(Res != 0) {
    printf("WSAStartup failed with error: %d\n", Res);
    return FALSE;
  }
#endif

  *ListenSocket = socket(PF_INET, SOCK_STREAM, 0);
  if(INVALID_SOCKET == *ListenSocket) {
    printf("Cannot create server listen socket.  Error is 0x%x\n", WSAGetLastError());
    return FALSE;
  }

  ZeroMem(&MyAddress, sizeof(MyAddress));
  MyAddress.sin_port = htons((short)PortNumber);
  MyAddress.sin_family = AF_INET;

  Res = bind(*ListenSocket, (struct sockaddr*) &MyAddress, sizeof(MyAddress));
  if(Res == SOCKET_ERROR) {
    printf("Bind error.  Error is 0x%x\n", WSAGetLastError());
    return FALSE;
  }

  Res = listen(*ListenSocket, 3);
  if(Res == SOCKET_ERROR) {
    printf("Listen error.  Error is 0x%x\n", WSAGetLastError());
    return FALSE;
  }
  return TRUE;
}

BOOLEAN
PlatformServer(
  IN SOCKET           Socket
  )
{
  BOOLEAN            Result;
  UINT32             Command;
  UINTN              BytesReceived;
  UINTN              BytesToReceive;

  while (TRUE) {
    BytesReceived = sizeof(mReceiveBuffer);
    Result = ReceivePlatformData (Socket, &Command, mReceiveBuffer, &BytesReceived);
    if (!Result) {
      printf ("ReceivePlatformData Error - %x\n", WSAGetLastError());
      return TRUE;
    }
    switch(GET_COMMAND_OPCODE(Command)) {
    case SOCKET_SPDM_COMMAND_TEST:
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_TEST, "Server Hello!", sizeof("Server Hello!"));
      if (!Result) {
        printf ("SendPlatformData Error - %x\n", WSAGetLastError());
        return TRUE;
      }
      break;
    case SOCKET_SPDM_COMMAND_NORMAL:
    case SOCKET_SPDM_COMMAND_SECURE:
      BytesToReceive = sizeof(mReceiveBuffer);
      Result = ProcessSpdmData (
                 Command,
                 mReceiveBuffer,
                 BytesReceived,
                 mReceiveBuffer,
                 &BytesToReceive
                 );
      if (!Result) {
        printf ("SendPlatformData Error - %x\n", WSAGetLastError());
        return TRUE;
      }
                
      Result = SendPlatformData (Socket, Command, mReceiveBuffer, BytesToReceive);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n", WSAGetLastError());
        return TRUE;
      }
      break;
    case SOCKET_SPDM_COMMAND_STOP:
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_STOP, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n", WSAGetLastError());
        return TRUE;
      }
      return FALSE;
      break;
    default:
      printf ("Unrecognized platform interface command %x\n", Command);
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_UNKOWN, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n", WSAGetLastError());
        return TRUE;
      }
      return TRUE;
    }
  }
}

BOOLEAN
PlatformServerRoutine (
  IN  UINT16           PortNumber
  )
{
  SOCKET               ListenSocket;
  SOCKET               ServerSocket;
  struct               sockaddr_in PeerAddress;
  BOOLEAN              Result;
  INT32                Length;
  BOOLEAN              ContinueServing;

  Result = CreateSocket(PortNumber, &ListenSocket);
  if (!Result) {
    printf ("Create platform service socket fail\n");
    return Result;
  }

  do {
    printf ("Platform server listening on port %d\n", PortNumber);

    Length = sizeof(PeerAddress);
    ServerSocket = accept(ListenSocket, (struct sockaddr*) &PeerAddress, &Length);
    if (ServerSocket == INVALID_SOCKET) {
      printf ("Accept error.  Error is 0x%x\n", WSAGetLastError());
#ifdef _MSC_VER
      WSACleanup();
#endif
      return FALSE;
    }
    printf ("Client accepted\n");

    ContinueServing = PlatformServer(ServerSocket);
    closesocket(ServerSocket);

  } while(ContinueServing);
#ifdef _MSC_VER
  WSACleanup();
#endif
  return TRUE;
}

int main (void)
{
  SpdmServerInit ();

  PlatformServerRoutine (DEFAULT_SPDM_PLATFORM_PORT);

  printf ("Server stopped\n");
  return 0;
}

