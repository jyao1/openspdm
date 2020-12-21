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

   <pre>
      SpdmDump -r <PcapFileName>
         [-q] (quite mode, dump message type only)
         [-a] (all mode, dump all fields)
         [-n] (dump ASN.1 certificate) -- TBD
         [-d] (dump application message)
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

1. If you use `SpdmDump -r <pcap_file>` to dump the SPDM message over MCTP, you may see something like:

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 290 (MCTP), MaxPacketSize - 65536
      1 (1608538700) MCTP(5) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION ()
      2 (1608538700) MCTP(5) RSP->REQ SPDM(10, 0x04) SPDM_VERSION (1.0.0.0, 1.1.0.0)
      3 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6)
      4 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6)
      5 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (Hash=0x00000001, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      6 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (Hash=0x00000001, MeasHash=0x00000002, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      7 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0x81) SPDM_GET_DIGESTS
      8 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x01) SPDM_DIGESTS
      9 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      10 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE
      11 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      12 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE
      13 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0x83) SPDM_CHALLENGE
      14 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x03) SPDM_CHALLENGE_AUTH
      15 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xea) SPDM_GET_ENCAPSULATED_REQUEST
      16 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6a) SPDM_ENCAPSULATED_REQUEST (ReqID=0x01) SPDM(11, 0x81) SPDM_GET_DIGESTS
      17 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x01) SPDM_DIGESTS
      18 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      19 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      20 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      21 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      22 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      23 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      24 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      25 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      26 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x83) SPDM_CHALLENGE
      27 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x03) SPDM_CHALLENGE_AUTH
      28 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x00) (Done)
      29 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS
      30 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS
      31 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS
      32 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS
      33 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS
      34 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS
      35 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS
      36 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS
      37 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS
      38 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS
      ......
   </pre>

   If the transport layer is PCI_DOE, you may see something like:

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 291 (PCI_DOE), MaxPacketSize - 65536
      ......
      7 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION ()
      8 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(10, 0x04) SPDM_VERSION (1.0.0.0, 1.1.0.0)
      9 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6)
      10 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6)
      11 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (Hash=0x00000001, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      12 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (Hash=0x00000001, MeasHash=0x00000002, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      13 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x81) SPDM_GET_DIGESTS
      14 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x01) SPDM_DIGESTS
      15 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      16 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE
      17 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      18 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE
      19 (1608544565) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x83) SPDM_CHALLENGE
      20 (1608544565) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x03) SPDM_CHALLENGE_AUTH
      ......
   </pre>

2. In order to dump the SPDM secure session, you need use `--psk` or `--dhe_secret`. `--req_cert_chain` and `--rsp_cert_chain` is also needed if GET_CERTIFICATE is not sent.

   The DHE secret can be found from SPDM debug message.
   Take [SpdmOsTest](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmOsTest.md) tool as an example, a user may use `SpdmRequesterEmu --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderEmu --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file, search "\[DHE Secret\]" or "\[PSK\]" in the log file to get the HEX string.

   ```
   [DHE Secret]: c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175
   ...
   [PSK]: 5465737450736b4461746100
   ```

   Then the user may use command `SpdmDump -r SpdmRequester.pcap --psk 5465737450736b4461746100 --dhe_secret c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175 --req_cert_chain Rsa2048/bundle_requester.certchain.der --rsp_cert_chain EcP256/bundle_responder.certchain.der`

   A full SPDM log is like below:

   <pre>
      ......
      39 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe4) SPDM_KEY_EXCHANGE (ReqSessionID=0xffff)
      40 (1608538701) MCTP(5) RSP->REQ SPDM(11, 0x64) SPDM_KEY_EXCHANGE_RSP (RspSessionID=0xffff, MutAuth=0x03, SlotID=0x00)
      41 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xea) SPDM_GET_ENCAPSULATED_REQUEST
      42 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6a) SPDM_ENCAPSULATED_REQUEST (ReqID=0x01) SPDM(11, 0x81) SPDM_GET_DIGESTS
      43 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x01) SPDM_DIGESTS
      44 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      45 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      46 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      47 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      48 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      49 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      50 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE
      51 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE
      52 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x00) (Done)
      53 (1608538701) MCTP(5) REQ->RSP SPDM(11, 0xe5) SPDM_FINISH (SigIncl=0x01, SlotNum=0x00)
      54 (1608538701) MCTP(5) RSP->REQ SPDM(11, 0x65) SPDM_FINISH_RSP ()
      55 (1608538701) MCTP(5) REQ->RSP SPDM(11, 0xe6) SPDM_PSK_EXCHANGE (ReqSessionID=0xfffe, PSKHint=5465737450736b48696e7400)
      56 (1608538701) MCTP(5) RSP->REQ SPDM(11, 0x66) SPDM_PSK_EXCHANGE_RSP (RspSessionID=0xfffe)
      57 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe7) SPDM_PSK_FINISH ()
      58 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x67) SPDM_PSK_FINISH_RSP ()
      59 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003)
      60 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003)
      61 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(1)
      62 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(1)
      63 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003)
      64 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003)
      65 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(1)
      66 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(1)
      67 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe8) SPDM_HEARTBEAT
      68 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x68) SPDM_HEARTBEAT_ACK
      69 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe8) SPDM_HEARTBEAT
      70 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x68) SPDM_HEARTBEAT_ACK
      71 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (UPDATE_KEY, Tag=0x6e)
      72 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (UPDATE_KEY, Tag=0x6e)
      73 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (VERIFY_NEW_KEY, Tag=0xad)
      74 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (VERIFY_NEW_KEY, Tag=0xad)
      75 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (UPDATE_ALL_KEYS, Tag=0xed)
      76 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (UPDATE_ALL_KEYS, Tag=0xed)
      77 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (VERIFY_NEW_KEY, Tag=0x76)
      78 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (VERIFY_NEW_KEY, Tag=0x76)
      79 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0xec) SPDM_END_SESSION
      80 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff) MCTP(5) SPDM(11, 0x6c) SPDM_END_SESSION_ACK
      81 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0xec) SPDM_END_SESSION
      82 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(5) SPDM(11, 0x6c) SPDM_END_SESSION_ACK
   </pre>

3. By default, SpdmDump only displays SPDM messge. If you want to dump other application message, you need use `-d`.

   Then you can see the MCTP message, such as:

   <pre>
      ......
      65 (1608538701) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe) MCTP(1) PLDM(0x80, 0x00, 0x02) (ID=0, D=0, Rq=1) ControlDiscovery GetTID_req ()
      66 (1608538701) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe) MCTP(1) PLDM(0x00, 0x00, 0x02, 0x00) (ID=0, D=0, Rq=0) ControlDiscovery GetTID_rsp (TID=0x01)
      ......
   </pre>

   or PCI_DOE message, such as:

   <pre>
      1 (1608544565) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=0)
      2 (1608544565) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 0, NextIndex=1)
      3 (1608544565) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=1)
      4 (1608544565) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 1, NextIndex=2)
      5 (1608544565) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=2)
      6 (1608544565) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 2, NextIndex=0)
      ......
   </pre>
   
   or PCI_IDE_KM message, such as:

   <pre>
      ......
      65 (1608544566) PCI_DOE(1, 2) REQ->RSP SecuredSPDM(0xffffffff) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x00) QUERY (Port=0x00)
      66 (1608544566) PCI_DOE(1, 2) RSP->REQ SecuredSPDM(0xffffffff) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x01) QUERY_RESP (Port=0x00, S00B00DF00, MaxPort=0x07)
      67 (1608544566) PCI_DOE(1, 2) REQ->RSP SecuredSPDM(0xfffefffe) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x00) QUERY (Port=0x00)
      68 (1608544566) PCI_DOE(1, 2) RSP->REQ SecuredSPDM(0xfffefffe) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x01) QUERY_RESP (Port=0x00, S00B00DF00, MaxPort=0x07)
      ......
   </pre>

4. You can also choose different dump level. By default, SpdmDump dumps most important fields. `-q` means quite mode, which only dumps header. `-a` means all mode, which dumps all fields as well as detailed parsing.

   Below is default dump:

   <pre>
      ......
      3 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6)
      4 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6)
      5 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (Hash=0x00000001, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      6 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (Hash=0x00000001, MeasHash=0x00000002, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
      ......
   </pre>

   Below is quite mode dump:

   <pre>
      ......
      3 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES
      4 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES
      5 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS
      6 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS
      ......
   </pre>

   Below is all mode dump:

   <pre>
      ......
      3 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6)
         Flags(CERT=1, CHAL=1, MEAS_NO_SIG=0, MEAS_SIG=1, MEAS_FRESH=0, ENCRYPT=1, MAC=1, MUT_AUTH=1, KEY_EX=1, PSK=1, ENCAP=1, HBEAT=1, KEY_UPD=1, HANDSHAKE_IN_CLEAR=1, PUB_KEY_ID=0)
      4 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6)
         Flags(CACHE=0, CERT=1, CHAL=1, MEAS_NO_SIG=0, MEAS_SIG=1, MEAS_FRESH=0, ENCRYPT=1, MAC=1, MUT_AUTH=1, KEY_EX=1, PSK=0, PSK_WITH_CONTEXT=1, ENCAP=1, HBEAT=1, KEY_UPD=1, HANDSHAKE_IN_CLEAR=1, PUB_KEY_ID=0)
      5 (1608538700) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (Hash=0x00000001, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
         Hash(SHA_256=1, SHA_384=0, SHA_512=0, SHA3_256=0, SHA3_384=0, SHA3_512=0)
         Asym(RSASSA_2048=0, RSASSA_3072=0, RSASSA_4096=0, RSAPSS_2048=0, RSAPSS_3072=0, RSAPSS_4096=0, ECDSA_P256=1, ECDSA_P384=0, ECDSA_P521=0)
         DHE(FFDHE_2048=0, FFDHE_3072=0, FFDHE_4096=0, SECP_256_R1=1, SECP_384_R1=0, SECP_521_R1=0)
         AEAD(AES_128_GCM=0, AES_256_GCM=1, CHACHA20_POLY1305=0)
         ReqAsym(RSASSA_2048=1, RSASSA_3072=0, RSASSA_4096=0, RSAPSS_2048=0, RSAPSS_3072=0, RSAPSS_4096=0, ECDSA_P256=0, ECDSA_P384=0, ECDSA_P521=0)
         KeySchedule(HMAC_HASH=1)
      6 (1608538700) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (Hash=0x00000001, MeasHash=0x00000002, Asym=0x00000010, DHE=0x0008, AEAD=0x0002, ReqAsym=0x0001, KeySchedule=0x0001)
         Hash(SHA_256)
         MeasHash(SHA_256)
         Asym(ECDSA_P256)
         DHE(SECP_256_R1)
         AEAD(AES_256_GCM)
         ReqAsym(RSASSA_2048)
         KeySchedule(HMAC_HASH)
      ......
   </pre>

   NOTE: Not all commands and fields are dumped so far. Please file issue or submit patch for them if you want to see something interesting.
