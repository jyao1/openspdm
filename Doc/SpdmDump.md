# SPDM Dump Tool

This document describes SpdmDump tool. It can be used to parse the SPDM message in a dump file offline.

## SPDM message dump file format

   We use [pcap](https://www.tcpdump.org/manpages/pcap-savefile.5.txt) file format.

   The packet must include the transport layer. We add below extension for [LinkType](https://www.tcpdump.org/linktypes.html).
   
   ```
   #define LINKTYPE_MCTP      290  // 0x0122
   #define LINKTYPE_PCI_DOE   291  // 0x0123
   ```

## SpdmDump user guide

   Use `SpdmDump -r <pcap_file>` to dump the SPDM message. You may see something like:

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 290 (MCTP), MaxPacketSize - 65536
      1 (1608173996) MCTP(5) SPDM(10, 0x84) REQ->RSP SPDM_GET_VERSION
      2 (1608173996) MCTP(5) SPDM(10, 0x04) RSP->REQ SPDM_VERSION
      3 (1608173996) MCTP(5) SPDM(11, 0xe1) REQ->RSP SPDM_GET_CAPABILITIES
      4 (1608173996) MCTP(5) SPDM(11, 0x61) RSP->REQ SPDM_CAPABILITIES
      5 (1608173996) MCTP(5) SPDM(11, 0xe3) REQ->RSP SPDM_NEGOTIATE_ALGORITHMS
      6 (1608173996) MCTP(5) SPDM(11, 0x63) RSP->REQ SPDM_ALGORITHMS
      7 (1608173996) MCTP(5) SPDM(11, 0x81) REQ->RSP SPDM_GET_DIGESTS
      8 (1608173996) MCTP(5) SPDM(11, 0x01) RSP->REQ SPDM_DIGESTS
      10 (1608452813) MCTP(5) SPDM(11, 0x02) RSP->REQ SPDM_CERTIFICATE
      11 (1608452813) MCTP(5) SPDM(11, 0x82) REQ->RSP SPDM_GET_CERTIFICATE
      12 (1608452813) MCTP(5) SPDM(11, 0x02) RSP->REQ SPDM_CERTIFICATE
      13 (1608452813) MCTP(5) SPDM(11, 0x83) REQ->RSP SPDM_CHALLENGE
      14 (1608452813) MCTP(5) SPDM(11, 0x03) RSP->REQ SPDM_CHALLENGE_AUTH
      15 (1608452813) MCTP(5) SPDM(11, 0xea) REQ->RSP SPDM_GET_ENCAPSULATED_REQUEST
      16 (1608452813) MCTP(5) SPDM(11, 0x6a) RSP->REQ SPDM_ENCAPSULATED_REQUEST SPDM_GET_DIGESTS
      17 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_DIGESTS
      18 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      19 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      20 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      21 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      22 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      23 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      24 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      25 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      26 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_CHALLENGE
      27 (1608452813) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CHALLENGE_AUTH
      28 (1608452813) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK (Done)
      29 (1608452813) MCTP(5) SPDM(11, 0xe0) REQ->RSP SPDM_GET_MEASUREMENTS
      30 (1608452813) MCTP(5) SPDM(11, 0x60) RSP->REQ SPDM_MEASUREMENTS
      31 (1608452813) MCTP(5) SPDM(11, 0xe0) REQ->RSP SPDM_GET_MEASUREMENTS
      32 (1608452813) MCTP(5) SPDM(11, 0x60) RSP->REQ SPDM_MEASUREMENTS
      33 (1608452813) MCTP(5) SPDM(11, 0xe0) REQ->RSP SPDM_GET_MEASUREMENTS
      34 (1608452813) MCTP(5) SPDM(11, 0x60) RSP->REQ SPDM_MEASUREMENTS
      35 (1608452813) MCTP(5) SPDM(11, 0xe0) REQ->RSP SPDM_GET_MEASUREMENTS
      36 (1608452813) MCTP(5) SPDM(11, 0x60) RSP->REQ SPDM_MEASUREMENTS
      37 (1608452813) MCTP(5) SPDM(11, 0xe0) REQ->RSP SPDM_GET_MEASUREMENTS
      38 (1608452813) MCTP(5) SPDM(11, 0x60) RSP->REQ SPDM_MEASUREMENTS
      ......
   </pre>

   or

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 291 (PCI_DOE), MaxPacketSize - 65536
      1 (1608173379) PCI_DOE(1, 1) SPDM(10, 0x84) REQ->RSP SPDM_GET_VERSION
      2 (1608173379) PCI_DOE(1, 1) SPDM(10, 0x04) RSP->REQ SPDM_VERSION
      3 (1608173379) PCI_DOE(1, 1) SPDM(11, 0xe1) REQ->RSP SPDM_GET_CAPABILITIES
      4 (1608173379) PCI_DOE(1, 1) SPDM(11, 0x61) RSP->REQ SPDM_CAPABILITIES
      5 (1608173379) PCI_DOE(1, 1) SPDM(11, 0xe3) REQ->RSP SPDM_NEGOTIATE_ALGORITHMS
      6 (1608173379) PCI_DOE(1, 1) SPDM(11, 0x63) RSP->REQ SPDM_ALGORITHMS
      ......
   </pre>

   In order to dump secured SPDM data, more parameters are required. See below:

   <pre>
      SpdmDump -r <PcapFileName>
         [-q] (quite mode, dump message type only)
         [-a] (all mode, dump all fields)
         [-n] (dump ASN.1 certificate) -- TBD
         [-d] (dump application message) -- TBD
         [-x] (dump message in hex)
         [--psk <pre-shared key>]
         [--dhe_secret <session DHE secret>]
         [--req_cert_chain <requester public cert chain file>]
         [--rsp_cert_chain <responder public cert chain file>]

      NOTE:
         [--psk] is required to decrypt a PSK session
         [--dhe_secret] is required to decrypt a non-PSK session
            Format: A hex string, whose count of char must be even.
                  It must not have prefix '0x'. The leading '0' must be included.
                  '0123CDEF' means 4 bytes 0x01, 0x23, 0xCD, 0xEF,
                  where 0x01 is the first byte and 0xEF is the last byte in memory

         [--req_cert_chain] is required to if GET_CERTIFICATE is not sent
         [--rsp_cert_chain] is required to if encapsulated GET_CERTIFICATE is not sent
            Format: A file containing certificates defined in SPDM spec 'certificate chain fomrat'.
                  It is one or more ASN.1 DER-encoded X.509 v3 certificates.
                  It may include multiple certificates, starting from root cert to leaf cert.
                  It does not include the Length, Reserved, or RootHash fields.
   </pre>

   The DHE secret can be found from SPDM debug message.
   Take SpdmRequesterEmu or SpdmResponderEmu as an example, a user may use `SpdmRequesterEmu --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderEmu --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file, search "\[DHE Secret\]" or "\[PSK\]" in the log file to get the HEX string.

   ```
   [DHE Secret]: c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175
   ...
   [PSK]: 5465737450736b4461746100
   ```

   Then the user may use command `SpdmDump -r SpdmRequester.pcap --psk 5465737450736b4461746100 --dhe_secret c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175 --req_cert_chain Rsa2048/bundle_requester.certchain.der --rsp_cert_chain EcP256/bundle_responder.certchain.der`

   A full SPDM log is like below:

   <pre>
      ......
      39 (1608429474) MCTP(5) SPDM(11, 0xe4) REQ->RSP SPDM_KEY_EXCHANGE
      40 (1608429474) MCTP(5) SPDM(11, 0x64) RSP->REQ SPDM_KEY_EXCHANGE_RSP
      41 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xea) REQ->RSP SPDM_GET_ENCAPSULATED_REQUEST
      42 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6a) RSP->REQ SPDM_ENCAPSULATED_REQUEST SPDM_GET_DIGESTS
      43 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_DIGESTS
      44 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      45 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      46 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      47 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      48 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      49 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      50 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK SPDM_GET_CERTIFICATE
      51 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) REQ->RSP SPDM_DELIVER_ENCAPSULATED_RESPONSE SPDM_CERTIFICATE
      52 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) RSP->REQ SPDM_ENCAPSULATED_RESPONSE_ACK (Done)
      53 (1608429474) MCTP(5) SPDM(11, 0xe5) REQ->RSP SPDM_FINISH
      54 (1608429474) MCTP(5) SPDM(11, 0x65) RSP->REQ SPDM_FINISH_RSP
      55 (1608429474) MCTP(5) SPDM(11, 0xe6) REQ->RSP SPDM_PSK_EXCHANGE
      56 (1608429474) MCTP(5) SPDM(11, 0x66) RSP->REQ SPDM_PSK_EXCHANGE_RSP
      57 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe7) REQ->RSP SPDM_PSK_FINISH
      58 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x67) RSP->REQ SPDM_PSK_FINISH_RSP
      59 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(10, 0xfe) REQ->RSP SPDM_VENDOR_DEFINED_REQUEST
      60 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(10, 0x7e) RSP->REQ SPDM_VENDOR_DEFINED_RESPONSE
      ......
      63 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(10, 0xfe) REQ->RSP SPDM_VENDOR_DEFINED_REQUEST
      64 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(10, 0x7e) RSP->REQ SPDM_VENDOR_DEFINED_RESPONSE
      ......
      67 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe8) REQ->RSP SPDM_HEARTBEAT
      68 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x68) RSP->REQ SPDM_HEARTBEAT_ACK
      69 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe8) REQ->RSP SPDM_HEARTBEAT
      70 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x68) RSP->REQ SPDM_HEARTBEAT_ACK
      71 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe9) REQ->RSP SPDM_KEY_UPDATE (UPDATE_KEY)
      72 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x69) RSP->REQ SPDM_KEY_UPDATE_ACK (UPDATE_KEY)
      73 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe9) REQ->RSP SPDM_KEY_UPDATE (VERIFY_NEW_KEY)
      74 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x69) RSP->REQ SPDM_KEY_UPDATE_ACK (VERIFY_NEW_KEY)
      75 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe9) REQ->RSP SPDM_KEY_UPDATE (UPDATE_ALL_KEYS)
      76 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x69) RSP->REQ SPDM_KEY_UPDATE_ACK (UPDATE_ALL_KEYS)
      77 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe9) REQ->RSP SPDM_KEY_UPDATE (VERIFY_NEW_KEY)
      78 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x69) RSP->REQ SPDM_KEY_UPDATE_ACK (VERIFY_NEW_KEY)
      79 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xec) REQ->RSP SPDM_END_SESSION
      80 (1608429474) MCTP(6) SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6c) RSP->REQ SPDM_END_SESSION_ACK
      81 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xec) REQ->RSP SPDM_END_SESSION
      82 (1608429474) MCTP(6) SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x6c) RSP->REQ SPDM_END_SESSION_ACK
   </pre>
