# openspdm library design. 

## SPDM libraries

1) SpdmRequesterLib (follows DSP0274)

   This library is linked for a SPDM requester.

2) SpdmResponderLib (follows DSP0274)

   This library is linked for a SPDM responder.

3) SpdmCommonLib (follows DSP0274)

   This library provides common services for SpdmRequesterLib and SpdmResponderLib.

4) SpdmEncodingLib (follows DSP0276)

   This library encrypts and decrypts secure SPDM messages.

5) SpdmDeviceLib (follows DSP0276, PCI DOE, etc)

   This library sends or receives SPDM message to or from a SPDM device.

   This library services should be provided by the SPDM requester or responder.

