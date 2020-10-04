# openspdm library design. 

## SPDM libraries

1) SpdmRequesterLib (follows DSP0274)

   This library is linked for a SPDM requester.

2) SpdmResponderLib (follows DSP0274)

   This library is linked for a SPDM responder.

3) SpdmCommonLib (follows DSP0274)

   This library provides common services for SpdmRequesterLib and SpdmResponderLib.

4) SpdmSecuredMessageLib (follows DSP0277)

   This library encrypts and decrypts secured messages.

5) SpdmTransportMctpLib (follows DSP0275 and DSP0276)

   This library encodes and decodes MTCP message header.

   SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC and SPDM_TRANSPORT_DECODE_MESSAGE_FUNC

   This API encodes or decodes transport layer message to or from a SPDM device.

6) SPDM_DEVICE_SEND_MESSAGE_FUNC and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC

   This API sends or receives transport layer message to or from a SPDM device.

