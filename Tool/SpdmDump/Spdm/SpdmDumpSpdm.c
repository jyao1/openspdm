/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

VOID               *mSpdmDecMessageBuffer;
VOID               *mSpdmContext;

VOID               *mSpdmLastMessageBuffer;
UINTN              mSpdmLastMessageBufferSize;
UINT32             mCachedSessionId;
SPDM_SESSION_INFO  *mCurrentSessionInfo;

BOOLEAN            mEncapsulated;

VOID
DumpSpdmGetVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  printf ("SPDM_GET_VERSION ");
  printf ("\n");

  SpdmContext = mSpdmContext;
  ResetManagedBuffer (&SpdmContext->Transcript.MessageA);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageB);
  ResetManagedBuffer (&SpdmContext->Transcript.MessageC);
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  printf ("SPDM_VERSION ");
  printf ("\n");

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmGetCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  printf ("SPDM_GET_CAPABILITIES ");
  printf ("\n");

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmCapabilities (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  printf ("SPDM_CAPABILITIES ");
  printf ("\n");

  SpdmContext = mSpdmContext;
  SpdmContext->ConnectionInfo.Capability.Flags = ((SPDM_CAPABILITIES_RESPONSE *)Buffer)->Flags;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmNegotiateAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;

  printf ("SPDM_NEGOTIATE_ALGORITHMS ");
  printf ("\n");

  SpdmContext = mSpdmContext;
  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmAlgorithms (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                                          Index;
  SPDM_NEGOTIATE_ALGORITHMS_COMMON_STRUCT_TABLE  *StructTable;

  printf ("SPDM_ALGORITHMS ");
  printf ("\n");

  SpdmContext = mSpdmContext;

  SpdmContext->ConnectionInfo.Algorithm.MeasurementHashAlgo = ((SPDM_ALGORITHMS_RESPONSE *)Buffer)->MeasurementHashAlgo;
  SpdmContext->ConnectionInfo.Algorithm.BaseAsymAlgo = ((SPDM_ALGORITHMS_RESPONSE *)Buffer)->BaseAsymSel;
  SpdmContext->ConnectionInfo.Algorithm.BaseHashAlgo = ((SPDM_ALGORITHMS_RESPONSE *)Buffer)->BaseHashSel;

  if (((SPDM_MESSAGE_HEADER *)Buffer)->SPDMVersion >= SPDM_MESSAGE_VERSION_11) {
    StructTable = (VOID *)((UINTN)Buffer +
                            sizeof(SPDM_ALGORITHMS_RESPONSE) +
                            sizeof(UINT32) * ((SPDM_ALGORITHMS_RESPONSE *)Buffer)->ExtAsymSelCount +
                            sizeof(UINT32) * ((SPDM_ALGORITHMS_RESPONSE *)Buffer)->ExtHashSelCount
                            );
    for (Index = 0; Index < ((SPDM_MESSAGE_HEADER *)Buffer)->Param1; Index++) {
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

  AppendManagedBuffer (&SpdmContext->Transcript.MessageA, Buffer, BufferSize);
}

VOID
DumpSpdmGetDigests (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_GET_DIGESTS ");
  printf ("\n");
}

VOID
DumpSpdmDigests (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_DIGESTS ");
  printf ("\n");
}

VOID
DumpSpdmGetCertificate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_GET_CERTIFICATE ");
  printf ("\n");
}

VOID
DumpSpdmCertificate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_CERTIFICATE ");
  printf ("\n");
}

VOID
DumpSpdmChallenge (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_CHALLENGE ");
  printf ("\n");
}

VOID
DumpSpdmChallengeAuth (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_CHALLENGE_AUTH ");
  printf ("\n");
}

VOID
DumpSpdmGetMeasurements (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_GET_MEASUREMENTS ");
  printf ("\n");
}

VOID
DumpSpdmMeasurements (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_MEASUREMENTS ");
  printf ("\n");
}

VOID
DumpSpdmRespondIfReady (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_RESPOND_IF_READY ");
  printf ("\n");
}

VOID
DumpSpdmError (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_ERROR ");
  printf ("\n");
}

VOID
DumpSpdmVendorDefinedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_VENDOR_DEFINED_REQUEST ");
  printf ("\n");
}

VOID
DumpSpdmVendorDefinedResponse (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_VENDOR_DEFINED_RESPONSE ");
  printf ("\n");
}

VOID
DumpSpdmKeyExchange (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_KEY_EXCHANGE ");
  printf ("\n");

  mCachedSessionId = (((SPDM_KEY_EXCHANGE_REQUEST *)Buffer)->ReqSessionID << 16);
  memcpy (mSpdmLastMessageBuffer, Buffer, BufferSize);
  mSpdmLastMessageBufferSize = BufferSize;
}

VOID
DumpSpdmKeyExchangeRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_DEVICE_CONTEXT  *SpdmContext;
  UINTN                HmacSize;

  printf ("SPDM_KEY_EXCHANGE_RSP ");
  printf ("\n");

  SpdmContext = mSpdmContext;

  mCachedSessionId = mCachedSessionId | ((SPDM_KEY_EXCHANGE_RESPONSE *)Buffer)->RspSessionID;
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId);
  ASSERT (mCurrentSessionInfo != NULL);
  mCurrentSessionInfo->UsePsk = FALSE;
  mCurrentSessionInfo->MutAuthRequested = ((SPDM_KEY_EXCHANGE_RESPONSE *)Buffer)->MutAuthRequested;

  HmacSize = GetSpdmHashSize (mSpdmContext);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize - HmacSize);
  } else {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize);
  }
  SpdmCalculateSessionHandshakeKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  if ((SpdmContext->ConnectionInfo.Capability.Flags & SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) == 0) {
    AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + BufferSize - HmacSize, HmacSize);
  }

  mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
}

VOID
DumpSpdmFinish (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_FINISH ");
  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);
}

VOID
DumpSpdmFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_FINISH_RSP ");
  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);

  SpdmCalculateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  mCurrentSessionInfo->SessionState = SpdmStateEstablished;
}

VOID
DumpSpdmPskExchange (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_PSK_EXCHANGE ");
  printf ("\n");

  mCachedSessionId = (((SPDM_PSK_EXCHANGE_REQUEST *)Buffer)->ReqSessionID << 16);
  memcpy (mSpdmLastMessageBuffer, Buffer, BufferSize);
  mSpdmLastMessageBufferSize = BufferSize;
}

VOID
DumpSpdmPskExchangeRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  UINTN                HmacSize;

  printf ("SPDM_PSK_EXCHANGE_RSP ");
  printf ("\n");

  mCachedSessionId = mCachedSessionId | ((SPDM_PSK_EXCHANGE_RESPONSE *)Buffer)->RspSessionID;
  mCurrentSessionInfo = SpdmAssignSessionId (mSpdmContext, mCachedSessionId);
  ASSERT (mCurrentSessionInfo != NULL);
  mCurrentSessionInfo->UsePsk = TRUE;

  HmacSize = GetSpdmHashSize (mSpdmContext);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, mSpdmLastMessageBuffer, mSpdmLastMessageBufferSize);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, Buffer, BufferSize - HmacSize);
  SpdmCalculateSessionHandshakeKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageK, (UINT8 *)Buffer + BufferSize - HmacSize, HmacSize);

  mCurrentSessionInfo->SessionState = SpdmStateHandshaking;
}

VOID
DumpSpdmPskFinish (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_PSK_FINISH ");
  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);
}

VOID
DumpSpdmPskFinishRsp (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_PSK_FINISH_RSP ");
  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  AppendManagedBuffer (&mCurrentSessionInfo->SessionTranscript.MessageF, Buffer, BufferSize);

  SpdmCalculateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, TRUE);
  mCurrentSessionInfo->SessionState = SpdmStateEstablished;
}

VOID
DumpSpdmHeartbeat (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT ");
  printf ("\n");
}

VOID
DumpSpdmHeartbeatAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_HEARTBEAT_ACK ");
  printf ("\n");
}

VOID
DumpSpdmKeyUpdate (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_KEY_UPDATE ");
  switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
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
  printf ("\n");

  ASSERT (mCurrentSessionInfo != NULL);
  switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
    SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionRequester);
    break;
  case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
    SpdmCreateUpdateSessionDataKey (mSpdmContext, mCurrentSessionInfo->SessionId, SpdmKeyUpdateActionAll);
    break;
  }
}

VOID
DumpSpdmKeyUpdateAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_KEY_UPDATE_ACK ");
  switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param1) {
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
  printf ("\n");
}

VOID
DumpSpdmGetEncapsulatedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_GET_ENCAPSULATED_REQUEST ");
  printf ("\n");
}

VOID
DumpSpdmEncapsulatedRequest (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_ENCAPSULATED_REQUEST ");
  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
  mEncapsulated = FALSE;
}

VOID
DumpSpdmDeliverEncapsulatedResponse (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_DELIVER_ENCAPSULATED_RESPONSE ");
  mEncapsulated = TRUE;
  DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
  mEncapsulated = FALSE;
}

VOID
DumpSpdmEncapsulatedResponseAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_ENCAPSULATED_RESPONSE_ACK ");
  switch (((SPDM_MESSAGE_HEADER *)Buffer)->Param2) {
  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
    printf ("(Done)");
    break;
  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
    mEncapsulated = TRUE;
    DumpSpdmMessage ((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER), BufferSize - sizeof(SPDM_MESSAGE_HEADER));
    mEncapsulated = FALSE;
    return ;
  case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_SLOT_NUMBER:
    printf ("(Slot(%d))", *((UINT8 *)Buffer + sizeof(SPDM_MESSAGE_HEADER)));
    break;
  }
  printf ("\n");
}

VOID
DumpSpdmEndSession (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_END_SESSION ");
  printf ("\n");
}

VOID
DumpSpdmEndSessionAck (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  printf ("SPDM_END_SESSION_ACK ");
  printf ("\n");
}

DISPATCH_TABLE_ENTRY mSpdmDispatch[] = {
  {SPDM_DIGESTS,                       "SPDM_DIGESTS",                       DumpSpdmDigests},
  {SPDM_CERTIFICATE,                   "SPDM_CERTIFICATE",                   DumpSpdmCertificate},
  {SPDM_CHALLENGE_AUTH,                "SPDM_CHALLENGE_AUTH",                DumpSpdmChallengeAuth},
  {SPDM_VERSION,                       "SPDM_VERSION",                       DumpSpdmVersion},
  {SPDM_MEASUREMENTS,                  "SPDM_MEASUREMENTS",                  DumpSpdmMeasurements},
  {SPDM_CAPABILITIES,                  "SPDM_CAPABILITIES",                  DumpSpdmCapabilities},
  {SPDM_ALGORITHMS,                    "SPDM_ALGORITHMS",                    DumpSpdmAlgorithms},
  {SPDM_VENDOR_DEFINED_RESPONSE,       "SPDM_VENDOR_DEFINED_RESPONSE",       DumpSpdmVendorDefinedResponse},
  {SPDM_ERROR,                         "SPDM_ERROR",                         DumpSpdmError},
  {SPDM_KEY_EXCHANGE_RSP,              "SPDM_KEY_EXCHANGE_RSP",              DumpSpdmKeyExchangeRsp},
  {SPDM_FINISH_RSP,                    "SPDM_FINISH_RSP",                    DumpSpdmFinishRsp},
  {SPDM_PSK_EXCHANGE_RSP,              "SPDM_PSK_EXCHANGE_RSP",              DumpSpdmPskExchangeRsp},
  {SPDM_PSK_FINISH_RSP,                "SPDM_PSK_FINISH_RSP",                DumpSpdmPskFinishRsp},
  {SPDM_HEARTBEAT_ACK,                 "SPDM_HEARTBEAT_ACK",                 DumpSpdmHeartbeatAck},
  {SPDM_KEY_UPDATE_ACK,                "SPDM_KEY_UPDATE_ACK",                DumpSpdmKeyUpdateAck},
  {SPDM_ENCAPSULATED_REQUEST,          "SPDM_ENCAPSULATED_REQUEST",          DumpSpdmEncapsulatedRequest},
  {SPDM_ENCAPSULATED_RESPONSE_ACK,     "SPDM_ENCAPSULATED_RESPONSE_ACK",     DumpSpdmEncapsulatedResponseAck},
  {SPDM_END_SESSION_ACK,               "SPDM_END_SESSION_ACK",               DumpSpdmEndSessionAck},

  {SPDM_GET_DIGESTS,                   "SPDM_GET_DIGESTS",                   DumpSpdmGetDigests},
  {SPDM_GET_CERTIFICATE,               "SPDM_GET_CERTIFICATE",               DumpSpdmGetCertificate},
  {SPDM_CHALLENGE,                     "SPDM_CHALLENGE",                     DumpSpdmChallenge},
  {SPDM_GET_VERSION,                   "SPDM_GET_VERSION",                   DumpSpdmGetVersion},
  {SPDM_GET_MEASUREMENTS,              "SPDM_GET_MEASUREMENTS",              DumpSpdmGetMeasurements},
  {SPDM_GET_CAPABILITIES,              "SPDM_GET_CAPABILITIES",              DumpSpdmGetCapabilities},
  {SPDM_NEGOTIATE_ALGORITHMS,          "SPDM_NEGOTIATE_ALGORITHMS",          DumpSpdmNegotiateAlgorithms},
  {SPDM_VENDOR_DEFINED_REQUEST,        "SPDM_VENDOR_DEFINED_REQUEST",        DumpSpdmVendorDefinedRequest},
  {SPDM_RESPOND_IF_READY,              "SPDM_RESPOND_IF_READY",              DumpSpdmRespondIfReady},
  {SPDM_KEY_EXCHANGE,                  "SPDM_KEY_EXCHANGE",                  DumpSpdmKeyExchange},
  {SPDM_FINISH,                        "SPDM_FINISH",                        DumpSpdmFinish},
  {SPDM_PSK_EXCHANGE,                  "SPDM_PSK_EXCHANGE",                  DumpSpdmPskExchange},
  {SPDM_PSK_FINISH,                    "SPDM_PSK_FINISH",                    DumpSpdmPskFinish},
  {SPDM_HEARTBEAT,                     "SPDM_HEARTBEAT",                     DumpSpdmHeartbeat},
  {SPDM_KEY_UPDATE,                    "SPDM_KEY_UPDATE",                    DumpSpdmKeyUpdate},
  {SPDM_GET_ENCAPSULATED_REQUEST,      "SPDM_GET_ENCAPSULATED_REQUEST",      DumpSpdmGetEncapsulatedRequest},
  {SPDM_DELIVER_ENCAPSULATED_RESPONSE, "SPDM_DELIVER_ENCAPSULATED_RESPONSE", DumpSpdmDeliverEncapsulatedResponse},
  {SPDM_END_SESSION,                   "SPDM_END_SESSION",                   DumpSpdmEndSession},
};

VOID
DumpSpdmMessage (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SPDM_MESSAGE_HEADER  *SpdmHeader;

  if (BufferSize < sizeof(SPDM_MESSAGE_HEADER)) {
    printf ("\n");
    return ;
  }

  SpdmHeader = Buffer;

  if (!mEncapsulated) {
    if ((SpdmHeader->RequestResponseCode & 0x80) != 0) {
      printf ("REQ->RSP ");
    } else {
      printf ("RSP->REQ ");
    }
  }
  printf ("SPDM(%x, 0x%02x) ", SpdmHeader->SPDMVersion, SpdmHeader->RequestResponseCode);

  DumpDispatchMessage (mSpdmDispatch, ARRAY_SIZE(mSpdmDispatch), SpdmHeader->RequestResponseCode, (UINT8 *)Buffer, BufferSize);

  if (!mEncapsulated) {
    if (mParamDumpHex) {
      printf ("  SPDM Message:\n");
      DumpHex (Buffer, BufferSize);
    }
  }
}

DISPATCH_TABLE_ENTRY mSecuredSpdmDispatch[] = {
  {LINKTYPE_MCTP,    "", DumpMctpMessage},
  {LINKTYPE_PCI_DOE, "", DumpSpdmMessage},
};

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
    DumpDispatchMessage (mSecuredSpdmDispatch, ARRAY_SIZE(mSecuredSpdmDispatch), GetDataLinkType(), mSpdmDecMessageBuffer, MessageSize);
  } else {
    //
    // Try other direction, because a responder might initiate a message in Session.
    //
    Status = SpdmDecodeSecuredMessage (
              mSpdmContext,
              SecuredMessageHeader->SessionId,
              !IsRequester,
              BufferSize,
              Buffer,
              &MessageSize,
              mSpdmDecMessageBuffer
              );
    if (!RETURN_ERROR(Status)) {
      IsRequester = !IsRequester;
      DumpDispatchMessage (mSecuredSpdmDispatch, ARRAY_SIZE(mSecuredSpdmDispatch), GetDataLinkType(), mSpdmDecMessageBuffer, MessageSize);
    } else {
      printf ("<Unknown>\n");
    }
  }

  if (mParamQuiteMode) {
    return ;
  }

  if (mParamDumpHex) {
    printf ("  SecuredSPDM Message:\n");
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