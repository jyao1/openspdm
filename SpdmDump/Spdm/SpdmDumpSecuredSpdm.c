/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmDump.h"

extern VOID               *mSpdmDecMessageBuffer;
extern VOID               *mSpdmContext;
extern VOID               *mCurrentSessionInfo;
extern UINT32             mCurrentSessionId;
extern BOOLEAN            mDecrypted;

VOID
DumpSpdmOpaqueVersionSelection (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SECURED_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION *VersionSelection;

  if (BufferSize < sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_VERSION_SELECTION)) {
    return ;
  }

  VersionSelection = Buffer;

  printf ("VERSION_SELECTION ");
  
  printf ("(%d.%d.%d.%d) ",
    VersionSelection->SelectedVersion.MajorVersion,
    VersionSelection->SelectedVersion.MinorVersion,
    VersionSelection->SelectedVersion.UpdateVersionNumber,
    VersionSelection->SelectedVersion.Alpha
    );
}

VOID
DumpSpdmOpaqueSupportedVersion (
  IN VOID    *Buffer,
  IN UINTN   BufferSize
  )
{
  SECURED_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION *SupportedVersion;
  SPDM_VERSION_NUMBER                              *SpdmVersionNumber;
  UINTN                                            Index;

  if (BufferSize < sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION)) {
    return ;
  }

  SupportedVersion = Buffer;
  if (BufferSize < sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_SUPPORTED_VERSION) + SupportedVersion->VersionCount * sizeof(SPDM_VERSION_NUMBER)) {
    return ;
  }

  printf ("SUPPORTED_VERSION ");

  SpdmVersionNumber = (VOID *)(SupportedVersion + 1);
  printf ("(");
  for (Index = 0; Index < SupportedVersion->VersionCount; Index ++) {
    if (Index != 0) {
      printf (", ");
    }
    printf ("%d.%d.%d.%d",
      SpdmVersionNumber[Index].MajorVersion,
      SpdmVersionNumber[Index].MinorVersion,
      SpdmVersionNumber[Index].UpdateVersionNumber,
      SpdmVersionNumber[Index].Alpha
      );
    printf (") ");
  }
}

DISPATCH_TABLE_ENTRY mSpdmOpaqueDispatch[] = {
  {SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,  "VERSION_SELECTION",  DumpSpdmOpaqueVersionSelection},
  {SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,  "SUPPORTED_VERSION",  DumpSpdmOpaqueSupportedVersion},
};

VOID
DumpSpdmOpaqueData (
  IN UINT8    *OpaqueData,
  IN UINT16   OpaqueLength
  )
{
  SECURED_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER  *SecuredMessageOpaqueDataTable;
  SECURED_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER       *SecuredMessageElementTable;
  SECURED_MESSAGE_OPAQUE_ELEMENT_HEADER             *SecuredMessageElement;
  UINTN                                             EndOfElementTable;
  UINTN                                             EndOfOpaqueData;
  UINTN                                             Index;
  CHAR8                                             *Ch;

  EndOfOpaqueData = (UINTN)OpaqueData + OpaqueLength;

  if (OpaqueLength < sizeof(SECURED_MESSAGE_GENERAL_OPAQUE_DATA_TABLE_HEADER)) {
    return ;
  }

  SecuredMessageOpaqueDataTable = (VOID *)OpaqueData;
  if (SecuredMessageOpaqueDataTable->SpecId != SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) {
    return ;
  }

  Ch = (VOID *)&SecuredMessageOpaqueDataTable->SpecId;
  printf ("\n      SecuredMessageOpaqueDataHeader(SpecId=0x%08x(%c%c%c%c), Ver=0x%02x, TotalElem=0x%02x)",
    SecuredMessageOpaqueDataTable->SpecId,
    Ch[3], Ch[2], Ch[1], Ch[0],
    SecuredMessageOpaqueDataTable->OpaqueVersion,
    SecuredMessageOpaqueDataTable->TotalElements
    );
  
  SecuredMessageElementTable = (VOID *)(SecuredMessageOpaqueDataTable + 1);
  for (Index = 0; Index < SecuredMessageOpaqueDataTable->TotalElements; Index++) {
    if ((UINTN)SecuredMessageElementTable + sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER) > EndOfOpaqueData) {
      break;
    }
    if (SecuredMessageElementTable->Id != SPDM_REGISTRY_ID_DMTF) {
      break;
    }
    if (SecuredMessageElementTable->VendorLen != 0) {
      break;
    }
    EndOfElementTable = (UINTN)SecuredMessageElementTable + sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_TABLE_HEADER) + SecuredMessageElementTable->OpaqueElementDataLen;
    if (EndOfElementTable > EndOfOpaqueData) {
      break;
    }
    printf ("\n      SecuredMessageOpaqueElement_%d(Id=0x%02x, Len=0x%04x) ",
      (UINT32)Index,
      SecuredMessageElementTable->Id,
      SecuredMessageElementTable->OpaqueElementDataLen
      );

    if (SecuredMessageElementTable->OpaqueElementDataLen < sizeof(SECURED_MESSAGE_OPAQUE_ELEMENT_HEADER)) {
      break;
    }
    SecuredMessageElement = (VOID *)(SecuredMessageElementTable + 1);
    printf ("Element(Ver=0x%02x, Id=0x%02x) ", SecuredMessageElement->SMDataVersion, SecuredMessageElement->SMDataID);

    DumpDispatchMessage (mSpdmOpaqueDispatch, ARRAY_SIZE(mSpdmOpaqueDispatch), SecuredMessageElement->SMDataID, (UINT8 *)SecuredMessageElement, SecuredMessageElementTable->OpaqueElementDataLen);

    SecuredMessageElementTable = (VOID *)EndOfElementTable;
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
  SPDM_SECURED_MESSAGE_ADATA_HEADER_1 *RecordHeader1;
  UINT16                              SequenceNum;
  UINTN                               SequenceNumSize;
  RETURN_STATUS                       Status;
  UINTN                               MessageSize;
  STATIC BOOLEAN                      IsRequester = FALSE;
  UINT32                              DataLinkType;
  SPDM_SECURED_MESSAGE_CALLBACKS      SpdmSecuredMessageCallbacks;
  VOID                                *SecuredMessageContext;

  DataLinkType = GetDataLinkType();
  switch (DataLinkType) {
  case LINKTYPE_MCTP:
    SequenceNumSize = sizeof(UINT16);
    SpdmSecuredMessageCallbacks.Version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    SpdmSecuredMessageCallbacks.GetSequenceNumber = MctpGetSequenceNumber;
    SpdmSecuredMessageCallbacks.GetMaxRandomNumberCount = MctpGetMaxRandomNumberCount;
    break;
  case LINKTYPE_PCI_DOE:
    SequenceNumSize = 0;
    SpdmSecuredMessageCallbacks.Version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    SpdmSecuredMessageCallbacks.GetSequenceNumber = PciDoeGetSequenceNumber;
    SpdmSecuredMessageCallbacks.GetMaxRandomNumberCount = PciDoeGetMaxRandomNumberCount;
    break;
  default:
    ASSERT (FALSE);
    printf ("<UnknownTransportLayer> ");
    printf ("\n");
    return ;
  }

  if (BufferSize < sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_1) + SequenceNumSize + sizeof(SPDM_SECURED_MESSAGE_ADATA_HEADER_2)) {
    printf ("\n");
    return ;
  }

  IsRequester = (BOOLEAN)(!IsRequester);

  RecordHeader1 = Buffer;
  SequenceNum = 0;
  if (DataLinkType == LINKTYPE_MCTP) {
    SequenceNum = *(UINT16 *)(RecordHeader1 + 1);
  }

  mCurrentSessionInfo = SpdmGetSessionInfoViaSessionId (mSpdmContext, RecordHeader1->SessionId);
  mCurrentSessionId = RecordHeader1->SessionId;
  Status = RETURN_UNSUPPORTED;
  if (mCurrentSessionInfo != NULL) {
    SecuredMessageContext = SpdmGetSecuredMessageContextViaSessionId (mSpdmContext, RecordHeader1->SessionId);
    if (SecuredMessageContext != NULL) {
      MessageSize = GetMaxPacketLength();
      Status = SpdmDecodeSecuredMessage (
                SecuredMessageContext,
                RecordHeader1->SessionId,
                IsRequester,
                BufferSize,
                Buffer,
                &MessageSize,
                mSpdmDecMessageBuffer,
                &SpdmSecuredMessageCallbacks
                );
      if (RETURN_ERROR(Status)) {
        //
        // Try other direction, because a responder might initiate a message in Session.
        //
        Status = SpdmDecodeSecuredMessage (
                  SecuredMessageContext,
                  RecordHeader1->SessionId,
                  !IsRequester,
                  BufferSize,
                  Buffer,
                  &MessageSize,
                  mSpdmDecMessageBuffer,
                  &SpdmSecuredMessageCallbacks
                  );
        if (!RETURN_ERROR(Status)) {
          IsRequester = !IsRequester;
        }
      }
    }
  }

  if (!RETURN_ERROR(Status)) {
    if (IsRequester) {
      printf ("REQ->RSP ");
    } else {
      printf ("RSP->REQ ");
    }
    printf ("SecuredSPDM(0x%08x", RecordHeader1->SessionId);
    if (DataLinkType == LINKTYPE_MCTP) {
      printf (", Seq=0x%04x", SequenceNum);
    }
    printf (") ");

    mDecrypted = TRUE;
    DumpDispatchMessage (mSecuredSpdmDispatch, ARRAY_SIZE(mSecuredSpdmDispatch), GetDataLinkType(), mSpdmDecMessageBuffer, MessageSize);
    mDecrypted = FALSE;
  } else {
    printf ("(?)->(?) ");
    printf ("SecuredSPDM(0x%08x", RecordHeader1->SessionId);
    if (DataLinkType == LINKTYPE_MCTP) {
      printf (", Seq=0x%04x", SequenceNum);
    }
    printf (") ");
    printf ("<Unknown> ");
    printf ("\n");
  }

  if (mParamDumpHex) {
    printf ("  SecuredSPDM Message:\n");
    DumpHex (Buffer, BufferSize);
  }
}
