/** @file
  SPDM Secured Message library.
  It follows the SPDM Specification.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SPDM_SECURED_MESSAGE_LIB_H__
#define __SPDM_SECURED_MESSAGE_LIB_H__

#include <Library/SpdmCommonLib.h>

/**
  Encode an application message to a secured message.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a source buffer to store the application message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a destination buffer to store the secured message.

  @retval RETURN_SUCCESS               The application message is encoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
**/
RETURN_STATUS
EFIAPI
SpdmEncodeSecuredMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                AppMessageSize,
  IN     VOID                 *AppMessage,
  IN OUT UINTN                *SecuredMessageSize,
     OUT VOID                 *SecuredMessage
  );

/**
  Decode an application message from a secured message.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  SessionId                    The session ID of the SPDM session.
  @param  IsRequester                  Indicates if it is a requester message.
  @param  SecuredMessageSize           Size in bytes of the secured message data buffer.
  @param  SecuredMessage               A pointer to a source buffer to store the secured message.
  @param  AppMessageSize               Size in bytes of the application message data buffer.
  @param  AppMessage                   A pointer to a destination buffer to store the application message.

  @retval RETURN_SUCCESS               The application message is decoded successfully.
  @retval RETURN_INVALID_PARAMETER     The Message is NULL or the MessageSize is zero.
  @retval RETURN_UNSUPPORTED           The SecuredMessage is unsupported.
**/
RETURN_STATUS
EFIAPI
SpdmDecodeSecuredMessage (
  IN     VOID                 *SpdmContext,
  IN     UINT32               SessionId,
  IN     BOOLEAN              IsRequester,
  IN     UINTN                SecuredMessageSize,
  IN     VOID                 *SecuredMessage,
  IN OUT UINTN                *AppMessageSize,
     OUT VOID                 *AppMessage
  );

/**
  Return the size in bytes of opaque data supproted version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return the size in bytes of opaque data supproted version.
**/
UINTN
EFIAPI
SpdmGetOpaqueDataSupportedVersionDataSize (
  IN     VOID                 *SpdmContext
  );

/**
  Build opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request generation.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataOutSize                  Size in bytes of the DataOut.
                                       On input, it means the size in bytes of DataOut buffer.
                                       On output, it means the size in bytes of copied DataOut buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired DataOut buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  DataOut                      A pointer to the desination buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

/**
  Process opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response parsing in requester.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataInSize                   Size in bytes of the DataIn.
  @param  DataIn                       A pointer to the buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is processed successfully.
  @retval RETURN_UNSUPPORTED           The DataIn is NOT opaque data version selection.
**/
RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

/**
  Return the size in bytes of opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @param  SpdmContext                  A pointer to the SPDM context.

  @return the size in bytes of opaque data version selection.
**/
UINTN
EFIAPI
SpdmGetOpaqueDataVersionSelectionDataSize (
  IN     VOID                 *SpdmContext
  );

/**
  Build opaque data version selection.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE response generation.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataOutSize                  Size in bytes of the DataOut.
                                       On input, it means the size in bytes of DataOut buffer.
                                       On output, it means the size in bytes of copied DataOut buffer if RETURN_SUCCESS is returned,
                                       and means the size in bytes of desired DataOut buffer if RETURN_BUFFER_TOO_SMALL is returned.
  @param  DataOut                      A pointer to the desination buffer to store the opaque data version selection.

  @retval RETURN_SUCCESS               The opaque data version selection is built successfully.
  @retval RETURN_BUFFER_TOO_SMALL      The buffer is too small to hold the data.
**/
RETURN_STATUS
EFIAPI
SpdmBuildOpaqueDataVersionSelectionData (
  IN     VOID                 *SpdmContext,
  IN OUT UINTN                *DataOutSize,
     OUT VOID                 *DataOut
  );

/**
  Process opaque data supported version.

  This function should be called in KEY_EXCHANGE/PSK_EXCHANGE request parsing in responder.

  @param  SpdmContext                  A pointer to the SPDM context.
  @param  DataInSize                   Size in bytes of the DataIn.
  @param  DataIn                       A pointer to the buffer to store the opaque data supported version.

  @retval RETURN_SUCCESS               The opaque data supported version is processed successfully.
  @retval RETURN_UNSUPPORTED           The DataIn is NOT opaque data supported version.
**/
RETURN_STATUS
EFIAPI
SpdmProcessOpaqueDataSupportedVersionData (
  IN     VOID                 *SpdmContext,
  IN     UINTN                DataInSize,
  IN     VOID                 *DataIn
  );

#endif