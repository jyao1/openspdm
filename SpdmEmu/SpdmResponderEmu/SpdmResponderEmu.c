/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmResponderEmu.h"

UINT32 mCommand;
UINTN  mReceiveBufferSize;
UINT8  mReceiveBuffer[MAX_SPDM_MESSAGE_BUFFER_SIZE];

SOCKET mServerSocket;

extern VOID *mSpdmContext;

VOID *
SpdmServerInit (
  VOID
  );

BOOLEAN
CreateSocket(
  IN  UINT16              PortNumber,
  IN  SOCKET              *ListenSocket
  )
{
  struct               sockaddr_in MyAddress;
  INT32                Res;

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
    printf("Cannot create server listen socket.  Error is 0x%x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    return FALSE;
  }

  ZeroMem(&MyAddress, sizeof(MyAddress));
  MyAddress.sin_port = htons((short)PortNumber);
  MyAddress.sin_family = AF_INET;

  Res = bind(*ListenSocket, (struct sockaddr*) &MyAddress, sizeof(MyAddress));
  if(Res == SOCKET_ERROR) {
    printf("Bind error.  Error is 0x%x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    closesocket(*ListenSocket);
    return FALSE;
  }

  Res = listen(*ListenSocket, 3);
  if(Res == SOCKET_ERROR) {
    printf("Listen error.  Error is 0x%x\n",
#ifdef _MSC_VER
      WSAGetLastError()
#else
      errno
#endif
      );
    closesocket(*ListenSocket);
    return FALSE;
  }
  return TRUE;
}

DOE_DISCOVERY_RESPONSE_MINE   mDoeResponse = {
  {
    PCI_DOE_VENDOR_ID_PCISIG,
    PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
    0,
    sizeof(mDoeResponse) / sizeof(UINT32), // Length
  },
  {
    PCI_DOE_VENDOR_ID_PCISIG,
    PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY,
    0x00
  },
};

BOOLEAN
PlatformServer (
  IN SOCKET           Socket
  )
{
  BOOLEAN            Result;
  RETURN_STATUS      Status;

  while (TRUE) {
    Status = SpdmResponderDispatchMessage (mSpdmContext);
    if (Status == RETURN_SUCCESS) {
      // success dispatch SPDM message
    }
    if (Status == RETURN_DEVICE_ERROR) {
      printf ("Server Critical Error - STOP\n");
      return FALSE;
    }
    if (Status != RETURN_UNSUPPORTED) {
      continue;
    }
    switch(mCommand) {
    case SOCKET_SPDM_COMMAND_TEST:
      Result = SendPlatformData (
                 Socket,
                 SOCKET_SPDM_COMMAND_TEST,
                 (UINT8 *)"Server Hello!",
                 sizeof("Server Hello!")
                 );
      if (!Result) {
        printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      break;

    case SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE:
      SpdmInitKeyUpdateEncapState (mSpdmContext);
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_OOB_ENCAP_KEY_UPDATE, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      break;

    case SOCKET_SPDM_COMMAND_SHUTDOWN:
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_SHUTDOWN, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      return FALSE;
      break;

    case SOCKET_SPDM_COMMAND_CONTINUE:
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_CONTINUE, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
        return TRUE;
      }
      return TRUE;
      break;

    case SOCKET_SPDM_COMMAND_NORMAL:
      if (mUseTransportLayer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
        DOE_DISCOVERY_REQUEST_MINE  *DoeRequest;

        DoeRequest = (VOID *)mReceiveBuffer;
        if ((DoeRequest->DoeHeader.VendorId != PCI_DOE_VENDOR_ID_PCISIG) ||
            (DoeRequest->DoeHeader.DataObjectType != PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY)) {
          // unknown message
          return TRUE;
        }
        ASSERT (mReceiveBufferSize == sizeof(DOE_DISCOVERY_REQUEST_MINE));
        ASSERT (DoeRequest->DoeHeader.Length == sizeof(*DoeRequest) / sizeof(UINT32));

        switch (DoeRequest->DoeDiscoveryRequest.Index) {
        case 0:
          mDoeResponse.DoeDiscoveryResponse.DataObjectType = PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY;
          mDoeResponse.DoeDiscoveryResponse.NextIndex = 1;
          break;
        case 1:
          mDoeResponse.DoeDiscoveryResponse.DataObjectType = PCI_DOE_DATA_OBJECT_TYPE_SPDM;
          mDoeResponse.DoeDiscoveryResponse.NextIndex = 2;
          break;
        case 2:
        default:
          mDoeResponse.DoeDiscoveryResponse.DataObjectType = PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
          mDoeResponse.DoeDiscoveryResponse.NextIndex = 0;
          break;
        }

        Result = SendPlatformData (
                  Socket,
                  SOCKET_SPDM_COMMAND_NORMAL,
                  (UINT8 *)&mDoeResponse,
                  sizeof(mDoeResponse)
                  );
        if (!Result) {
          printf ("SendPlatformData Error - %x\n",
  #ifdef _MSC_VER
            WSAGetLastError()
  #else
            errno
  #endif
            );
          return TRUE;
        }
      } else {
        // unknown message
        return TRUE;
      }
      break;

    default:
      printf ("Unrecognized platform interface command %x\n", mCommand);
      Result = SendPlatformData (Socket, SOCKET_SPDM_COMMAND_UNKOWN, NULL, 0);
      if (!Result) {
        printf ("SendPlatformData Error - %x\n",
#ifdef _MSC_VER
          WSAGetLastError()
#else
          errno
#endif
          );
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
  struct               sockaddr_in PeerAddress;
  BOOLEAN              Result;
  UINT32               Length;
  BOOLEAN              ContinueServing;

  Result = CreateSocket(PortNumber, &ListenSocket);
  if (!Result) {
    printf ("Create platform service socket fail\n");
    return Result;
  }

  do {
    printf ("Platform server listening on port %d\n", PortNumber);

    Length = sizeof(PeerAddress);
    mServerSocket = accept(ListenSocket, (struct sockaddr*) &PeerAddress, (socklen_t *)&Length);
    if (mServerSocket == INVALID_SOCKET) {
      printf ("Accept error.  Error is 0x%x\n",
#ifdef _MSC_VER
        WSAGetLastError()
#else
        errno
#endif
        );
#ifdef _MSC_VER
      WSACleanup();
#endif
      closesocket(ListenSocket);
      return FALSE;
    }
    printf ("Client accepted\n");

    ContinueServing = PlatformServer(mServerSocket);
    closesocket(mServerSocket);

  } while(ContinueServing);
#ifdef _MSC_VER
  WSACleanup();
#endif
  closesocket(ListenSocket);
  return TRUE;
}

int main (
  int argc,
  char *argv[ ]
  )
{
  printf ("%s version 0.1\n", "SpdmResponderEmu");
  srand((unsigned int)time(NULL));

  ProcessArgs ("SpdmResponderEmu", argc, argv);

  mSpdmContext = SpdmServerInit ();
  if (mSpdmContext == NULL) {
    return 0;
  }

  PlatformServerRoutine (DEFAULT_SPDM_PLATFORM_PORT);

  free (mSpdmContext);

  printf ("Server stopped\n");

  ClosePcapPacketFile ();
  return 0;
}

