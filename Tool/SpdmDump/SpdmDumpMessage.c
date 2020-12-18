/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID               *mSpdmLastMessageBuffer;
UINTN              mSpdmLastMessageBufferSize;
VOID               *mSpdmDecMessageBuffer;
VOID               *mSpdmContext;
SPDM_SESSION_INFO  *mCurrentSessionInfo;

typedef struct {
  UINT8 OpCode;
  CHAR8 *String;
} SPDM_OPCODE_STRING_ENTRY;

SPDM_OPCODE_STRING_ENTRY mSpdmOpcodeStringTable[] = {
  {SPDM_DIGESTS, "SPDM_DIGESTS"},
  {SPDM_CERTIFICATE, "SPDM_CERTIFICATE"},
  {SPDM_CHALLENGE_AUTH, "SPDM_CHALLENGE_AUTH"},
  {SPDM_VERSION, "SPDM_VERSION"},
  {SPDM_MEASUREMENTS, "SPDM_MEASUREMENTS"},
  {SPDM_CAPABILITIES, "SPDM_CAPABILITIES"},
  {SPDM_ALGORITHMS, "SPDM_ALGORITHMS"},
  {SPDM_VENDOR_DEFINED_RESPONSE, "SPDM_VENDOR_DEFINED_RESPONSE"},
  {SPDM_ERROR, "SPDM_ERROR"},
  {SPDM_KEY_EXCHANGE_RSP, "SPDM_KEY_EXCHANGE_RSP"},
  {SPDM_FINISH_RSP, "SPDM_FINISH_RSP"},
  {SPDM_PSK_EXCHANGE_RSP, "SPDM_PSK_EXCHANGE_RSP"},
  {SPDM_PSK_FINISH_RSP, "SPDM_PSK_FINISH_RSP"},
  {SPDM_HEARTBEAT_ACK, "SPDM_HEARTBEAT_ACK"},
  {SPDM_KEY_UPDATE_ACK, "SPDM_KEY_UPDATE_ACK"},
  {SPDM_ENCAPSULATED_REQUEST, "SPDM_ENCAPSULATED_REQUEST"},
  {SPDM_ENCAPSULATED_RESPONSE_ACK, "SPDM_ENCAPSULATED_RESPONSE_ACK"},
  {SPDM_END_SESSION_ACK, "SPDM_END_SESSION_ACK"},

  {SPDM_GET_DIGESTS, "SPDM_GET_DIGESTS"},
  {SPDM_GET_CERTIFICATE, "SPDM_GET_CERTIFICATE"},
  {SPDM_CHALLENGE, "SPDM_CHALLENGE"},
  {SPDM_GET_VERSION, "SPDM_GET_VERSION"},
  {SPDM_GET_MEASUREMENTS, "SPDM_GET_MEASUREMENTS"},
  {SPDM_GET_CAPABILITIES, "SPDM_GET_CAPABILITIES"},
  {SPDM_NEGOTIATE_ALGORITHMS, "SPDM_NEGOTIATE_ALGORITHMS"},
  {SPDM_VENDOR_DEFINED_REQUEST, "SPDM_VENDOR_DEFINED_REQUEST"},
  {SPDM_RESPOND_IF_READY, "SPDM_RESPOND_IF_READY"},
  {SPDM_KEY_EXCHANGE, "SPDM_KEY_EXCHANGE"},
  {SPDM_FINISH, "SPDM_FINISH"},
  {SPDM_PSK_EXCHANGE, "SPDM_PSK_EXCHANGE"},
  {SPDM_PSK_FINISH, "SPDM_PSK_FINISH"},
  {SPDM_HEARTBEAT, "SPDM_HEARTBEAT"},
  {SPDM_KEY_UPDATE, "SPDM_KEY_UPDATE"},
  {SPDM_GET_ENCAPSULATED_REQUEST, "SPDM_GET_ENCAPSULATED_REQUEST"},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE, "SPDM_DELIVER_ENCAPSULATED_RESPONSE"},
  {SPDM_END_SESSION, "SPDM_END_SESSION"},
};

CHAR8 *
SpdmOpCodeToString (
  IN UINT8  SpdmOpCode
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE(mSpdmOpcodeStringTable); Index++) {
    if (SpdmOpCode == mSpdmOpcodeStringTable[Index].OpCode) {
      return mSpdmOpcodeStringTable[Index].String;
    }
  }
  return "<Unknown>";
}

VOID
DumpSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_MESSAGE_HEADER  *SpdmHeader;
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  STATIC UINT32        CachedSessionId = 0;
  SPDM_MESSAGE_HEADER  *EncSpdmHeader;
  UINTN                HmacSize;

  if (BufferSize < sizeof(SPDM_MESSAGE_HEADER)) {
    return ;
  }

  SpdmHeader = Buffer;

  printf ("SPDM(%x, 0x%02x) ", SpdmHeader->SPDMVersion, SpdmHeader->RequestResponseCode);

  if ((SpdmHeader->RequestResponseCode & 0x80) != 0) {
    printf ("REQ->RSP ");
  } else {
    printf ("RSP->REQ ");
  }

  printf ("%s ", SpdmOpCodeToString(SpdmHeader->RequestResponseCode));

  SpdmContext = mSpdmContext;
  switch (SpdmHeader->RequestResponseCode) {
  case SPDM_KEY_UPDATE:
  case SPDM_KEY_UPDATE_ACK:
    switch (SpdmHeader->Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      printf ("(UPDATE_KEY) ");
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
      printf ("(UPDATE_ALL_KEYS) ");
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY:
      printf ("(VERIFY_NEW_KEY) ");
      break;
    }
    break;
  case SPDM_ENCAPSULATED_REQUEST:
  case SPDM_DELIVER_ENCAPSULATED_RESPONSE:
    EncSpdmHeader = SpdmHeader + 1;
    printf ("%s ", SpdmOpCodeToString(EncSpdmHeader->RequestResponseCode));
    break;
  case SPDM_ENCAPSULATED_RESPONSE_ACK:
    EncSpdmHeader = SpdmHeader + 1;
    switch (SpdmHeader->Param2) {
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
      printf ("(Done)");
      break;
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
      printf ("%s ", SpdmOpCodeToString(EncSpdmHeader->RequestResponseCode));
      break;
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER:
      printf ("(Slot(%d))", *(UINT8 *)EncSpdmHeader);
      break;
    }
    break;
  }

  printf ("\n");

  switch (SpdmHeader->RequestResponseCode) {
  case SPDM_GET_VERSION:
    ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
    ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
    ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;
  case SPDM_VERSION:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;
  case SPDM_GET_CAPABILITIES:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;
  case SPDM_CAPABILITIES:
    SpdmContext->ConnectionInfo.Capability.Flags = ((SPDM_CAPABILITIES_RESPONSE *)SpdmHeader)->Flags;
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;
  case SPDM_NEGOTIATE_ALGORITHMS:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;
  case SPDM_ALGORITHMS:
    {
      UINTN                                          Index;
      SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;

      SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = ((SPDM_ALGORITHMS_RESPONSE *)SpdmHeader)->MeasurementHashAlgo;
      SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = ((SPDM_ALGORITHMS_RESPONSE *)SpdmHeader)->BaseAsymSel;
      SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = ((SPDM_ALGORITHMS_RESPONSE *)SpdmHeader)->BaseHashSel;

      if (SpdmHeader->SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
        StructTable = (VOID *)((UINTN)SpdmHeader +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            sizeof(UINT32) * ((SPDM_ALGORITHMS_RESPONSE *)SpdmHeader)->ExtAsymSelCount +
                            sizeof(UINT32) * ((SPDM_ALGORITHMS_RESPONSE *)SpdmHeader)->ExtHashSelCount
                            );
        for (Index = 0; Index < SpdmHeader->Param1; Index++) {
          switch (StructTable[Index].AlgType) {
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
            SpdmContext->ConnectionInfo.Algorithm.DHENamedGroup = StructTable[Index].AlgSupported;
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
            SpdmContext->ConnectionInfo.Algorithm.AEADCipherSuite = StructTable[Index].AlgSupported;
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
            SpdmContext->ConnectionInfo.Algorithm.ReqBaseAsymAlg = StructTable[Index].AlgSupported;
            break;
          case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
            SpdmContext->ConnectionInfo.Algorithm.KeySchedule = StructTable[Index].AlgSupported;
            break;
          }
        }
      }
    }
    AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
    break;

  case SPDM_GET_DIGESTS:
  case SPDM_DIGESTS:
  case SPDM_GET_CERTIFICATE:
  case SPDM_CERTIFICATE:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageB, Buffer, BufferSize);
    break;
  case SPDM_CHALLENGE:
  case SPDM_CHALLENGE_AUTH:
    AppendManagedBuffer (&SpdmContext->Transcript.MessageC, Buffer, BufferSize);
    break;

  case SPDM_KEY_EXCHANGE:
    CachedSessionId = (((SPDM_KEY_EXCHANGE_REQUEST *)SpdmHeader)->ReqSessionID << 16);
    memcpy (mSpdmLastMessageBuffer, Buffer, BufferSize);
    mSpdmLastMessageBufferSize = BufferSize;
    break;
  case SPDM_KEY_EXCHANGE_RSP:
    CachedSessionId = CachedSessionId | ((SPDM_KEY_EXCHANGE_RESPONSE *)SpdmHeader)->RspSessionID;
    mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, CachedSessionId);
    ASSERT (mCurrentSessionInfo != NULL);
    mCurrentSessionInfo->UsePsk = FALSE;
    mCurrentSessionInfo->MutAuthRequested = ((SPDM_KEY_EXCHANGE_RESPONSE *)SpdmHeader)->MutAuthRequested;

    HmacSize = GetSpdmHashSize (mSpdmContext);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
    if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
      AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize - HmacSize);
    } else {
      AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize);
    }
    SpdmCalculateSessionHandshakeKey (mSpdmContext, CachedSessionId, TRUE);
    if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
      AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + BufferSize - HmacSize, HmacSize);
    }

    mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
    break;
  case SPDM_FINISH:
    ASSERT (mCurrentSessionInfo != NULL);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);
    break;
  case SPDM_FINISH_RSP:
    ASSERT (mCurrentSessionInfo != NULL);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);

    SpdmCalculateSessionDataKey (mSpdmContext, CachedSessionId, TRUE);
    mCurrentSessionInfo->SessionState = SpdmStateEstablished;
    break;

  case SPDM_PSK_EXCHANGE:
    CachedSessionId = (((SPDM_PSK_EXCHANGE_REQUEST *)SpdmHeader)->ReqSessionID << 16);
    memcpy (mSpdmLastMessageBuffer, Buffer, BufferSize);
    mSpdmLastMessageBufferSize = BufferSize;
    break;
  case SPDM_PSK_EXCHANGE_RSP:
    CachedSessionId = CachedSessionId | ((SPDM_PSK_EXCHANGE_RESPONSE *)SpdmHeader)->RspSessionID;
    mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, CachedSessionId);
    ASSERT (mCurrentSessionInfo != NULL);
    mCurrentSessionInfo->UsePsk = TRUE;

    HmacSize = GetSpdmHashSize (mSpdmContext);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize - HmacSize);
    SpdmCalculateSessionHandshakeKey (mSpdmContext, CachedSessionId, TRUE);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + BufferSize - HmacSize, HmacSize);

    mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
    break;
  case SPDM_PSK_FINISH:
    ASSERT (mCurrentSessionInfo != NULL);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);
    break;
  case SPDM_PSK_FINISH_RSP:
    ASSERT (mCurrentSessionInfo != NULL);
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);

    SpdmCalculateSessionDataKey (mSpdmContext, CachedSessionId, TRUE);
    mCurrentSessionInfo->SessionState = SpdmStateEstablished;
    break;

  case SPDM_KEY_UPDATE:
    ASSERT (mCurrentSessionInfo != NULL);
    switch (SpdmHeader->Param1) {
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
      SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionRequester);
      break;
    case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
      SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionAll);
      break;
    }
    break;
  }

  if (mParamQuiteMode) {
    return ;
  }

  if (mParamDumpHex) {
    DumpHex (Buffer, BufferSize);
  }
}

VOID
DumpSecuredSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_SECURED_MESSAGE_ADATA_HEADER  *SecuredMessageHeader;
  RETURN_STATUS                       Status;
  UINTN                               MessageSize;
  STATIC BOOLEAN                      IsRequester = FALSE;

  if (BufferSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER)) {
    return ;
  }

  SecuredMessageHeader = Buffer;
  IsRequester = (BOOLEAN)(!IsRequester);

  printf ("SecuredSPDM(0x%08x) ", SecuredMessageHeader->SessionId);

  mCurrentSessionInfo = SpdmGetSessionInfoViaSessionId (mSpdmContext, SecuredMessageHeader->SessionId);

  if (mParamQuiteMode) {
    printf ("\n");
    return ;
  }

  MessageSize = GetMaxPacketLength();
  Status = SpdmDecodeSecuredMessage (
             mSpdmContext,
             SecuredMessageHeader->SessionId,
             IsRequester,
             BufferSize,
             Buffer,
             &MessageSize,
             mSpdmDecMessageBuffer
             );
  if (!RETURN_ERROR(Status)) {
    if (GetDataLinkType() == LINKTYPE_MCTP) {
      DumpMctpMessage (mSpdmDecMessageBuffer, MessageSize);
    } else if (GetDataLinkType() == LINKTYPE_PCI_DOE) {
      DumpSpdmMessage (mSpdmDecMessageBuffer, MessageSize);
    }      
  } else {
    printf ("<Unknown>\n");
  }

  if (mParamDumpHex) {
    DumpHex (Buffer, BufferSize);
  }
}

BOOLEAN
InitSpdmDump (
  VOID
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  mSpdmDecMessageBuffer = (VOID *)malloc (GetMaxPacketLength());
  if (mSpdmDecMessageBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  mSpdmLastMessageBuffer = (VOID *)malloc (GetMaxPacketLength());
  if (mSpdmLastMessageBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }

  mSpdmContext = (VOID *)malloc (SpdmGetContextSize());
  if (mSpdmContext == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  SpdmInitContext (mSpdmContext);

  SpdmContext = mSpdmContext;
  SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer = (VOID *)malloc (MAX_SPDM_MESSAGE_BUFFER_SIZE);
  if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    goto Error;
  }
  
  return TRUE;

Error:
  if (mSpdmDecMessageBuffer != NULL) {
    free (mSpdmDecMessageBuffer);
    mSpdmDecMessageBuffer = NULL;
  }
  if (mSpdmLastMessageBuffer != NULL) {
    free (mSpdmLastMessageBuffer);
    mSpdmLastMessageBuffer = NULL;
  }
  if (mSpdmContext != NULL) {
    if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
      free (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer);
    }
    free (mSpdmContext);
    mSpdmContext = NULL;
  }
  return FALSE;
}

VOID
DeinitSpdmDump (
  VOID
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  free (mSpdmDecMessageBuffer);
  free (mSpdmLastMessageBuffer);

  SpdmContext = mSpdmContext;
  if (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer == NULL) {
    free (SpdmContext->ConnectionInfo.LocalUsedCertChainBuffer);
  }
  free (mSpdmContext);
}