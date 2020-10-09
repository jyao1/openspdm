# openspdm library design. 

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
          | | |                  ^                  | | |
          | | |                  |                  | | |
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

   This library encrypts and decrypts secured messages.

5) [SpdmTransportMctpLib](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmTransportMctpLib.h) (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM requester/responder need register SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC
   and SPDM_TRANSPORT_DECODE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

6) SPDM_DEVICE_SEND_MESSAGE_FUNC and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC

   SPDM requester/responder need register SPDM_DEVICE_SEND_MESSAGE_FUNC
   and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These APIs send and receive transport layer messages to or from a SPDM device.

7) [SpdmLibConfig.h](https://github.com/jyao1/openspdm/blob/master/Include/Library/SpdmLibConfig.h) provides the configuration to the openspdm library.

8) SPDM library depends upon the [HAL library](https://github.com/jyao1/openspdm/tree/master/Include/Hal).

   The sample implementation can be found at [OsStub](https://github.com/jyao1/openspdm/tree/master/OsStub)

   8.1) [BaseCryptLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseCryptLib.h) provides crypto functions.

   8.2) [BaseMemoryLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/BaseMemoryLib.h) provides memory operation.

   8.3) [DebugLib](https://github.com/jyao1/openspdm/blob/master/Include/Hal/Library/DebugLib.h) provides debug functions.
