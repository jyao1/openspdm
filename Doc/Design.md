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

1) SpdmRequesterLib (follows DSP0274)

   This library is linked for a SPDM requester.

2) SpdmResponderLib (follows DSP0274)

   This library is linked for a SPDM responder.

3) SpdmCommonLib (follows DSP0274)

   This library provides common services for SpdmRequesterLib and SpdmResponderLib.

4) SpdmSecuredMessageLib (follows DSP0277)

   This library encrypts and decrypts secured messages.

5) SpdmTransportMctpLib (follows DSP0275 and DSP0276)

   This library encodes and decodes MCTP message header.

   SPDM requester/responder need register SPDM_TRANSPORT_ENCODE_MESSAGE_FUNC
   and SPDM_TRANSPORT_DECODE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These two APIs encode and decode transport layer messages to or from a SPDM device.

6) SPDM_DEVICE_SEND_MESSAGE_FUNC and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC

   SPDM requester/responder need register SPDM_DEVICE_SEND_MESSAGE_FUNC
   and SPDM_DEVICE_RECEIVE_MESSAGE_FUNC to the SpdmRequesterLib/SpdmResponderLib.

   These APIs send and receive transport layer messages to or from a SPDM device.
