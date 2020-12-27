# openspdm library design.

1. Use static link (Library), when there is one instance can be linked to the device.
   For example, crypto engine.

2. Use dynamic link (function registration), when there are multiple instances can be linked to the device.
   For example, transport layer.

## SPDM library layer

   ```
        +================+               +================+
        | SPDM Requester |               | SPDM Responder |       // PCI Component Measurement and Authentication (CMA)
        | Device Driver  |               | Device Driver  |       // PCI Integrity and Data Encryption (IDE)
        +================+               +================+
               | SpdmSendReceiveData               ^ SPDM_GET_RESPONSE_FUNC
   =============================================================
               V                                   |
   +------------------+  +---------------+  +------------------+
   | SpdmRequesterLib |->| SpdmCommonLib |<-| SpdmResponderLib |  // DSP0274 - SPDM
   +------------------+  +---------------+  +------------------+
          | | |             |         V             | | |
          | | |             | +-------------------+ | | |
          | | |             | |SpdmDeviceSecretLib| | | |         // Device Secret handling (PrivateKey)
          | | |             | +-------------------+ | | |
          | | |             V         ^             | | |
          | | |      +-----------------------+      | | |
          | |  ----->| SpdmSecuredMessageLib |<-----  | |         // DSP0277 - Secured Message in SPDM session
          | |        +-----------------------+        | |
          | |                    ^                    | |
   =============================================================
          | |                    |                    | |
          | |         +---------------------+         | |
          |  -------->| SpdmTransportXXXLib |<--------  |         // DSP0275/DSP0276 - SPDM/SecuredMessage over MCTP
          |           | (XXX = Mctp, PciDoe)|           |         // PCI Data Object Exchange (DOE) message
          |           +---------------------+           |
          |  SPDM_TRANSPORT_ENCODE/DECODE_MESSAGE_FUNC  |
          |                                             |
   =============================================================
          |                                             |
          |    SPDM_DEVICE_SEND/RECEIVE_MESSAGE_FUNC    |
          |             +----------------+              |
           ------------>| SPDM Device IO |<-------------         // DSP0237 - MCTP over SMBus
                        | (SMBus, PciDoe)|                       // DSP0238 - MCTP over PCIeVDM
                        +----------------+                       // PCI DOE - PCI DOE message over PCI DOE mailbox.
   ```

1) [SpdmRequesterLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmRequesterLib.h) (follows DSP0274)

   This library is linked for a SPDM requester.

2) [SpdmResponderLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmResponderLib.h) (follows DSP0274)

   This library is linked for a SPDM responder.

3) [SpdmCommonLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmCommonLib.h) (follows DSP0274)

   This library provides common services for SpdmRequesterLib and SpdmResponderLib.

4) [SpdmSecuredMessageLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmSecuredMessageLib.h) (follows DSP0277)

   This library handles the session key generation and secured messages encryption and decryption.

   This can be implemented in a secure environment, if the session keys are considered as secret.

5) [SpdmDeviceSecretLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmDeviceSecretLib.h)

   This library handles the private key singing, PSK HMAC operation and measurement collection.

   This must be implemented in a secure environment, because the private key and PSK are secret.

6) [SpdmCryptLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmCryptLib.h)

   This library provides SPDM related crypto function. It is based upon [BaseCryptLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseCryptLib.h).

7) SpdmTransportLib

7.1) [SpdmTransportMctpLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmTransportMctpLib.h) (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM requester/responder need register SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC
   and SPDM_TRANSPORT_DECODE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

7.2) [SpdmTransportPciDoeLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmTransportPciDoeLib.h) (follows PCI DOE)

   This library encodes and decodes PCI DOE message header.

   SPDM requester/responder need register SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC
   and SPDM_TRANSPORT_DECODE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

8) SPDM_DEVICE_SEND_MESSAGE_FUNC and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC

   SPDM requester/responder need register SPDM_DEVICE_SEND_MESSAGE_FUNC
   and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These APIs send and receive transport layer messages to or from a SPDM device.

9) [SpdmLibConfig.h](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmLibConfig.h) provides the configuration to the openspdm library.

10) SPDM library depends upon the [HAL library](https://github.com/jyao1/openspdm/tree/master/Include/Hal).

   The sample implementation can be found at [OsStub](https://github.com/jyao1/openspdm/tree/master/OsStub)

   10.1) [BaseCryptLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseCryptLib.h) provides crypto functions.

   10.2) [BaseMemoryLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseMemoryLib.h) provides memory operation.

   10.3) [DebugLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/DebugLib.h) provides debug functions.
