/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterTest.h"

#define IP_ADDRESS "127.0.0.1"

#ifdef _MSC_VER
struct  in_addr mIpAddress = {{{127, 0, 0, 1}}};
#else
struct  in_addr mIpAddress = {0x0100007F};
#endif
UINT8  mReceiveBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

extern SOCKET                       mSocket;

VOID
SpdmClientInit (
  VOID
  );

BOOLEAN
CommunicatePlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT32           Session,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend,
  OUT UINT32          *Response,
  OUT UINT32          *RspSession,
  IN OUT UINTN        *BytesToReceive,
  OUT UINT8           *ReceiveBuffer
  );

RETURN_STATUS
DoMeasurementViaSpdm (
  VOID
  );

RETURN_STATUS
DoAuthenticationViaSpdm (
  VOID
  );

RETURN_STATUS
DoSessionViaSpdm (
  VOID
  );

BOOLEAN
InitClient (
  OUT SOCKET  *Socket,
  IN  UINT16  Port
  )
{
  SOCKET             ClientSocket;
  struct sockaddr_in ServerAddr;
  INT32              Return;

  ClientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ClientSocket == INVALID_SOCKET) {
    printf ("Create Socket Failed - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return FALSE;
  }

  ServerAddr.sin_family = AF_INET;
  CopyMem (&ServerAddr.sin_addr.s_addr, &mIpAddress, sizeof(struct in_addr));
  ServerAddr.sin_port = htons(Port);
  ZeroMem (ServerAddr.sin_zero, sizeof(ServerAddr.sin_zero));

  Return = connect (ClientSocket, (struct sockaddr *)&ServerAddr, sizeof(ServerAddr));
  if (Return == SOCKET_ERROR) {
    printf ("Connect Error - %x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return FALSE;
  }

  printf ("connect success!\n");

  *Socket = ClientSocket;
  return TRUE;
}

BOOLEAN
PlatformClientRoutine (
  IN UINT16 PortNumber
)
{
  SOCKET  PlatformSocket;
  BOOLEAN Result;
  UINT32  Response;
  UINTN   ResponseSize;
  UINT32  Session;
  
#ifdef _MSC_VER
  WSADATA Ws;
  if (WSAStartup(MAKEWORD(2,2), &Ws) != 0) {
    printf ("Init Windows Socket Failed - %x\n", WSAGetLastError());
    return FALSE;
  }
#endif
  Result = InitClient (&PlatformSocket, PortNumber);
  if (!Result) {
    return FALSE;
  }
  
  mSocket = PlatformSocket;
  SpdmClientInit ();

  ResponseSize = sizeof(mReceiveBuffer);
  Result = CommunicatePlatformData (
             PlatformSocket,
             SOCKET_SPDM_COMMAND_TEST,
             0,
             (UINT8 *)"Client Hello!",
             sizeof("Client Hello!"),
             &Response,
             &Session,
             &ResponseSize,
             mReceiveBuffer
             );
  if (!Result) {
    return FALSE;
  }

  // Do test - begin

  DoMeasurementViaSpdm ();

  DoAuthenticationViaSpdm ();

  DoSessionViaSpdm ();

  // Do test - end

  ResponseSize = 0;
  Result = CommunicatePlatformData (
             PlatformSocket,
             SOCKET_SPDM_COMMAND_STOP,
             0,
             NULL,
             0,
             &Response,
             &Session,
             &ResponseSize,
             NULL
             );

  closesocket (PlatformSocket);
  
#ifdef _MSC_VER
  WSACleanup();
#endif

  return TRUE;
}


int main (void)
{
  PlatformClientRoutine (DEFAULT_SPDM_PLATFORM_PORT);
  printf ("Client stopped\n");
}