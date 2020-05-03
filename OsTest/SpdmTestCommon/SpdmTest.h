/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_TEST_H__
#define __SPDM_TEST_H__

#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SpdmCommonLib.h>

#include "WinInclude.h"
#include "stdio.h"
#include "SpdmTestCommand.h"

#define USE_PSK 0

VOID
DumpData (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  );

BOOLEAN
SendPlatformData (
  IN SOCKET           Socket,
  IN UINT32           Command,
  IN UINT8            *SendBuffer,
  IN UINTN            BytesToSend
  );

BOOLEAN
ReceivePlatformData (
  IN  SOCKET           Socket,
  OUT UINT32           *Command,
  OUT UINT8            *ReceiveBuffer,
  IN OUT UINTN         *BytesToReceive
  );

BOOLEAN
ReadInputFile (
  IN CHAR8    *FileName,
  OUT UINT8   **FileData,
  OUT UINTN   *FileSize
  );

BOOLEAN
WriteOutputFile (
  IN CHAR8   *FileName,
  IN UINT8   *FileData,
  IN UINTN   FileSize
  );

BOOLEAN
ReadPrivateCertificate (
  OUT UINT8   **Data,
  OUT UINTN   *Size
  );

BOOLEAN
ReadPublicCertificateChain (
  OUT UINT8   **Data,
  OUT UINTN   *Size
  );

#endif