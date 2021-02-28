# SpdmDump Tool

This document describes SpdmDump tool. It can be used to parse the SPDM message in a dump file offline.

## SPDM message dump file format

   We use [pcap](https://www.tcpdump.org/manpages/pcap-savefile.5.txt) file format.

   The packet must include the transport layer. We add below extension for [LinkType](https://www.tcpdump.org/linktypes.html).
   
   ```
   #define LINKTYPE_MCTP      291  // 0x0123
   #define LINKTYPE_PCI_DOE   292  // 0x0124
   ```

## SpdmDump user guide

   <pre>
      SpdmDump -r <PcapFileName>
         [-q] (quite mode, dump message type only)
         [-a] (all mode, dump all fields)
         [-d] (dump application message)
         [-x] (dump message in hex)
         [--psk <pre-shared key>]
         [--dhe_secret <session DHE secret>]
         [--req_cap       CERT|CHAL|                                ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|                 ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]
         [--rsp_cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]
         [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--meas_spec DMTF]
         [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]
         [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]
         [--key_schedule HMAC_HASH]
         [--req_cert_chain <input requester public cert chain file>]
         [--rsp_cert_chain <input responder public cert chain file>]
         [--out_req_cert_chain <output requester public cert chain file>]
         [--out_rsp_cert_chain <output responder public cert chain file>]

      NOTE:
         [--psk] is required to decrypt a PSK session
         [--dhe_secret] is required to decrypt a non-PSK session
            Format: A hex string, whose count of char must be even.
                  It must not have prefix '0x'. The leading '0' must be included.
                  '0123CDEF' means 4 bytes 0x01, 0x23, 0xCD, 0xEF,
                  where 0x01 is the first byte and 0xEF is the last byte in memory

         [--req_cap] and [--rsp_cap] means requester capability flags and responder capability flags.
            Format: Capabilities can be multiple flags. Please use ',' for them.
         [--hash], [--meas_spec], [--meas_hash], [--asym], [--req_asym], [--dhe], [--aead], [--key_schedule] means negotiated algorithms.
            Format: Algorithms must include only one flag.
            Capabilities and algorithms are required if GET_CAPABILITIES or NEGOTIATE_ALGORITHMS is not sent.
                  For example, the negotiated state session or quick PSK session.

         [--req_cert_chain] is required to if encapsulated GET_CERTIFICATE is not sent
         [--rsp_cert_chain] is required to if GET_CERTIFICATE is not sent
         [--out_req_cert_chain] can be used to if encapsulated GET_CERTIFICATE is sent
         [--out_rsp_cert_chain] can be used to if GET_CERTIFICATE is sent
            Format: A file containing certificates defined in SPDM spec 'certificate chain fomrat'.
                  It is one or more ASN.1 DER-encoded X.509 v3 certificates.
                  It may include multiple certificates, starting from root cert to leaf cert.
                  It does not include the Length, Reserved, or RootHash fields.
   </pre>

1. If you use `SpdmDump -r <pcap_file>` to dump the SPDM message over MCTP, you may see something like:

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 290 (MCTP), MaxPacketSize - 65536
      1 (1608625474) MCTP(5) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION ()
      2 (1608625474) MCTP(5) RSP->REQ SPDM(10, 0x04) SPDM_VERSION (1.0.0.0, 1.1.0.0)
      3 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6, CTExponent=0x00)
      4 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6, CTExponent=0x00)
      5 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (MeasSpec=0x01(DMTF), Hash=0x00000001(SHA_256), Asym=0x00000010(ECDSA_P256), DHE=0x0008(SECP_256_R1), AEAD=0x0002(AES_256_GCM), ReqAsym=0x0001(RSASSA_2048), KeySchedule=0x0001(HMAC_HASH))
      6 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (MeasSpec=0x01(DMTF), Hash=0x00000001(SHA_256), MeasHash=0x00000002(SHA_256), Asym=0x00000010(ECDSA_P256), DHE=0x0008(SECP_256_R1), AEAD=0x0002(AES_256_GCM), ReqAsym=0x0001(RSASSA_2048), KeySchedule=0x0001(HMAC_HASH))
      7 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0x81) SPDM_GET_DIGESTS ()
      8 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x01) SPDM_DIGESTS (SlotMask=0x03)
      9 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x0, Length=0x400)
      10 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x144)
      11 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x400, Length=0x400)
      12 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x144, RemLen=0x0)
      13 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0x83) SPDM_CHALLENGE (SlotID=0x00, HashType=0x00(NoHash))
      14 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x03) SPDM_CHALLENGE_AUTH (Attr=0x80(BasicMutAuth, SlotID=0x00), SlotMask=0x01)
      15 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xea) SPDM_GET_ENCAPSULATED_REQUEST ()
      16 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6a) SPDM_ENCAPSULATED_REQUEST (ReqID=0x01) SPDM(11, 0x81) SPDM_GET_DIGESTS ()
      17 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x01) SPDM_DIGESTS (SlotMask=0x03)
      18 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x0, Length=0x400)
      19 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x9d4)
      20 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x400, Length=0x400)
      21 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x5d4)
      22 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x800, Length=0x400)
      23 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x1d4)
      24 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0xc00, Length=0x400)
      25 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x1d4, RemLen=0x0)
      26 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x83) SPDM_CHALLENGE (SlotID=0x00, HashType=0x00(NoHash))
      27 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x03) SPDM_CHALLENGE_AUTH (Attr=0x00(, SlotID=0x00), SlotMask=0x01)
      28 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x00) (Done)
      29 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x00(TotalNum))
      30 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (TotalMeasIndex=0x04)
      31 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x01)
      32 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
      33 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x02)
      34 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
      35 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x03)
      36 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
      37 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x01(GenSig), MeasOp=0x04, SlotID=0x00)
      38 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27, SlotID=0x00)
      ......
   </pre>

   If the transport layer is PCI_DOE, you may see something like:

   <pre>
      PcapFile: Magic - 'a1b2c3d4', version2.4, DataLink - 291 (PCI_DOE), MaxPacketSize - 65536
      1 (1608626133) PCI_DOE(1, 0)
      2 (1608626133) PCI_DOE(1, 0)
      3 (1608626133) PCI_DOE(1, 0)
      4 (1608626133) PCI_DOE(1, 0)
      5 (1608626133) PCI_DOE(1, 0)
      6 (1608626133) PCI_DOE(1, 0)
      7 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION ()
      8 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(10, 0x04) SPDM_VERSION (1.0.0.0, 1.1.0.0)
      9 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6, CTExponent=0x00)
      10 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6, CTExponent=0x00)
      11 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS (MeasSpec=0x01(DMTF), Hash=0x00000001(SHA_256), Asym=0x00000010(ECDSA_P256), DHE=0x0008(SECP_256_R1), AEAD=0x0002(AES_256_GCM), ReqAsym=0x0001(RSASSA_2048), KeySchedule=0x0001(HMAC_HASH))
      12 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS (MeasSpec=0x01(DMTF), Hash=0x00000001(SHA_256), MeasHash=0x00000002(SHA_256), Asym=0x00000010(ECDSA_P256), DHE=0x0008(SECP_256_R1), AEAD=0x0002(AES_256_GCM), ReqAsym=0x0001(RSASSA_2048), KeySchedule=0x0001(HMAC_HASH))
      13 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x81) SPDM_GET_DIGESTS ()
      14 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x01) SPDM_DIGESTS (SlotMask=0x03)
      15 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x0, Length=0x400)
      16 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x144)
      17 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x400, Length=0x400)
      18 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x144, RemLen=0x0)
      19 (1608626133) PCI_DOE(1, 1) REQ->RSP SPDM(11, 0x83) SPDM_CHALLENGE (SlotID=0x00, HashType=0x00(NoHash))
      20 (1608626133) PCI_DOE(1, 1) RSP->REQ SPDM(11, 0x03) SPDM_CHALLENGE_AUTH (Attr=0x80(BasicMutAuth, SlotID=0x00), SlotMask=0x01)
      ......
   </pre>

2. In order to dump the SPDM secure session, you need use `--psk` or `--dhe_secret`.

   The DHE secret can be found from SPDM debug message.
   Take [SpdmEmu](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmEmu.md) tool as an example, a user may use `SpdmRequesterEmu --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderEmu --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file, search "\[DHE Secret\]" or "\[PSK\]" in the log file to get the HEX string.

   ```
   [DHE Secret]: c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175
   ...
   [PSK]: 5465737450736b4461746100
   ```

   Then the user may use command `SpdmDump -r SpdmRequester.pcap --psk 5465737450736b4461746100 --dhe_secret c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175`

   A full SPDM log is like below:

   <pre>
      ......
      39 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe4) SPDM_KEY_EXCHANGE (HashType=0x01(TcbHash), SlotID=0x00, ReqSessionID=0xffff)
      40 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x64) SPDM_KEY_EXCHANGE_RSP (Heart=0x00, RspSessionID=0xffff, MutAuth=0x03(Requested,WithEncap), SlotID=0x00)
      41 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0000) MCTP(5) SPDM(11, 0xea) SPDM_GET_ENCAPSULATED_REQUEST ()
      42 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0000) MCTP(5) SPDM(11, 0x6a) SPDM_ENCAPSULATED_REQUEST (ReqID=0x01) SPDM(11, 0x81) SPDM_GET_DIGESTS ()
      43 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0001) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x01) SPDM_DIGESTS (SlotMask=0x03)
      44 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0001) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x0, Length=0x400)
      45 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0002) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x9d4)
      46 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0002) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x400, Length=0x400)
      47 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0003) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x5d4)
      48 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0003) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0x800, Length=0x400)
      49 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0004) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x400, RemLen=0x1d4)
      50 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0004) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x01) SPDM(11, 0x82) SPDM_GET_CERTIFICATE (SlotID=0x00, Offset=0xc00, Length=0x400)
      51 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0005) MCTP(5) SPDM(11, 0xeb) SPDM_DELIVER_ENCAPSULATED_RESPONSE (ReqID=0x01) SPDM(11, 0x02) SPDM_CERTIFICATE (SlotID=0x00, PortLen=0x1d4, RemLen=0x0)
      52 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0005) MCTP(5) SPDM(11, 0x6b) SPDM_ENCAPSULATED_RESPONSE_ACK (ReqID=0x00) (Done)
      53 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe5) SPDM_FINISH (Attr=0x01 (SigIncl=1), SlotID=0x00)
      54 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x65) SPDM_FINISH_RSP ()
      55 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe6) SPDM_PSK_EXCHANGE (HashType=0x01(TcbHash), ReqSessionID=0xfffe, PSKHint=5465737450736b48696e7400)
      56 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x66) SPDM_PSK_EXCHANGE_RSP (Heart=0x00, RspSessionID=0xfffe)
      57 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0xe7) SPDM_PSK_FINISH ()
      58 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0x67) SPDM_PSK_FINISH_RSP ()
      59 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0000) MCTP(5) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003)
      60 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0000) MCTP(5) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003)
      61 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0001) MCTP(1)
      62 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0001) MCTP(1)
      63 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003)
      64 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003)
      65 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(1)
      66 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(1)
      67 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0002) MCTP(5) SPDM(11, 0xe8) SPDM_HEARTBEAT ()
      68 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0002) MCTP(5) SPDM(11, 0x68) SPDM_HEARTBEAT_ACK ()
      69 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0002) MCTP(5) SPDM(11, 0xe8) SPDM_HEARTBEAT ()
      70 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0002) MCTP(5) SPDM(11, 0x68) SPDM_HEARTBEAT_ACK ()
      71 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0003) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (KeyOp=0x01(UpdateKey), Tag=0xc0)
      72 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0003) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (KeyOp=0x01(UpdateKey), Tag=0xc0)
      73 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0000) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (KeyOp=0x03(VerifyNewKey), Tag=0x77)
      74 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0004) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (KeyOp=0x03(VerifyNewKey), Tag=0x77)
      75 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0003) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (KeyOp=0x02(UpdateAllkeys), Tag=0xfc)
      76 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (KeyOp=0x02(UpdateAllkeys), Tag=0xfc)
      77 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0xe9) SPDM_KEY_UPDATE (KeyOp=0x03(VerifyNewKey), Tag=0x37)
      78 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(5) SPDM(11, 0x69) SPDM_KEY_UPDATE_ACK (KeyOp=0x03(VerifyNewKey), Tag=0x37)
      79 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xffffffff, Seq=0x0001) MCTP(5) SPDM(11, 0xec) SPDM_END_SESSION (Attr=0x00())
      80 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xffffffff, Seq=0x0005) MCTP(5) SPDM(11, 0x6c) SPDM_END_SESSION_ACK ()
      81 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(5) SPDM(11, 0xec) SPDM_END_SESSION (Attr=0x00())
      82 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0002) MCTP(5) SPDM(11, 0x6c) SPDM_END_SESSION_ACK ()
   </pre>

3. If GET_CERTIFICATE or encapsulated GET_CERTIFICATE is not sent (e.g. when SlotId 0xFF is used or PUB_KEY_ID is used), the user need use `--rsp_cert_chain` or `--req_cert_chain` to indicate the responder certificate chain or the requester certificate chain, to dump the secured session data.

   For example, `SpdmDump -r SpdmRequester.pcap --psk 5465737450736b4461746100 --dhe_secret c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175 --req_cert_chain Rsa3072/bundle_requester.certchain.der --rsp_cert_chain EcP384/bundle_responder.certchain.der`

   If GET_CERTIFICATE or encapsulated GET_CERTIFICATE is sent, the user may use `--out_rsp_cert_chain` or `--out_req_cert_chain` to get the responder certificate chain or the requester certificate chain.
   
   Then the user may use other tool to view the certificate chain, such as `openssl x509 -in cert.der -inform der -noout -text` or `openssl asn1parse -in cert.der -inform der`.

4. If GET_CAPABILITIES or NEGOTIATE_ALGORITHMS is not sent (e.g. when negotiated state is used or quick PSK path is used), the user need indicate the capabilities and algorithms to dump the rest data.

   For example, `SpdmDump -r SpdmNegotiatedState.pcap --psk 5465737450736b4461746100 --dhe_secret c7ac17ee29b6a4f84e978223040b7eddff792477a6f7fc0f51faa553fee58175 --req_cap CERT,CHAL,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR --rsp_cap CACHE,CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK_WITH_CONTEXT,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR --hash SHA_384 --meas_spec DMTF --meas_hash SHA_512 --asym ECDSA_P384 --req_asym RSAPSS_3072 --dhe SECP_384_R1 --aead AES_256_GCM --key_schedule HMAC_HASH`

5. By default, SpdmDump only displays SPDM messge. If you want to dump other application message, you need use `-d`.

   Then you can see the MCTP message, such as:

   <pre>
      ......
      65 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(1) PLDM(0x80, 0x00, 0x02) (ID=0, D=0, Rq=1) ControlDiscovery GetTID_req ()
      66 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0001) MCTP(1) PLDM(0x00, 0x00, 0x02, 0x00) (ID=0, D=0, Rq=0) ControlDiscovery GetTID_rsp (TID=0x01)
      ......
   </pre>

   or PCI_DOE message, such as:

   <pre>
      1 (1608626133) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=0)
      2 (1608626133) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 0, NextIndex=1)
      3 (1608626133) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=1)
      4 (1608626133) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 1, NextIndex=2)
      5 (1608626133) PCI_DOE(1, 0) REQ->RSP DOE_DISCOVERY (Index=2)
      6 (1608626133) PCI_DOE(1, 0) RSP->REQ DOE_DISCOVERY (1, 2, NextIndex=0)
      ......
   </pre>
   
   or PCI_IDE_KM message, such as:

   <pre>
      ......
      65 (1608626133) PCI_DOE(1, 2) REQ->RSP SecuredSPDM(0xffffffff) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x00) QUERY (Port=0x00)
      66 (1608626133) PCI_DOE(1, 2) RSP->REQ SecuredSPDM(0xffffffff) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x01) QUERY_RESP (Port=0x00, S00B00DF00, MaxPort=0x07)
      67 (1608626133) PCI_DOE(1, 2) REQ->RSP SecuredSPDM(0xfffefffe) SPDM(10, 0xfe) SPDM_VENDOR_DEFINED_REQUEST (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x00) QUERY (Port=0x00)
      68 (1608626133) PCI_DOE(1, 2) RSP->REQ SecuredSPDM(0xfffefffe) SPDM(10, 0x7e) SPDM_VENDOR_DEFINED_RESPONSE (StandID=0x0003) PCI (VendorID=0x0001) (ProtID=0x00) IDE_KM(0x01) QUERY_RESP (Port=0x00, S00B00DF00, MaxPort=0x07)
      ......
   </pre>

6. You can also choose different dump level. By default, SpdmDump dumps most important fields. `-q` means quite mode, which only dumps header. `-a` means all mode, which dumps all fields as well as detailed parsing. `-x` means to dump the message in hex.

   Below is quite mode dump:

   <pre>
      1 (1608625474) MCTP(5) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION
      2 (1608625474) MCTP(5) RSP->REQ SPDM(10, 0x04) SPDM_VERSION
      3 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES
      4 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES
      5 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe3) SPDM_NEGOTIATE_ALGORITHMS
      6 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x63) SPDM_ALGORITHMS
      ......
   </pre>

   Below is all mode dump:

   <pre>
      ......
      3 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe1) SPDM_GET_CAPABILITIES (Flags=0x0000f7d6, CTExponent=0x00)
          Flags(CERT=1, CHAL=1, MEAS_NO_SIG=0, MEAS_SIG=1, MEAS_FRESH=0, ENCRYPT=1, MAC=1, MUT_AUTH=1, KEY_EX=1, PSK=1, ENCAP=1, HBEAT=1, KEY_UPD=1, HANDSHAKE_IN_CLEAR=1, PUB_KEY_ID=0)
      4 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x61) SPDM_CAPABILITIES (Flags=0x0000fbd6, CTExponent=0x00)
          Flags(CACHE=0, CERT=1, CHAL=1, MEAS_NO_SIG=0, MEAS_SIG=1, MEAS_FRESH=0, ENCRYPT=1, MAC=1, MUT_AUTH=1, KEY_EX=1, PSK=0, PSK_WITH_CONTEXT=1, ENCAP=1, HBEAT=1, KEY_UPD=1, HANDSHAKE_IN_CLEAR=1, PUB_KEY_ID=0)
      ......
      13 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0x83) SPDM_CHALLENGE (SlotID=0x00, HashType=0x00(NoHash))
         Nonce(4d 71 80 cf 9d 6f f6 60 53 59 5c 02 30 b4 b3 03 60 cd a6 ae 0d fb c0 b7 2f 24 dd d9 a1 82 de bd)
      14 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x03) SPDM_CHALLENGE_AUTH (Attr=0x80(BasicMutAuth, SlotID=0x00), SlotMask=0x01)
         CertChainHash(0f 73 ea f4 47 25 cd 38 84 1c 18 d4 ed 3a 5c 4b 0a f7 d0 e3 90 7d ec 54 cd 8f 3e ec 7c 2f e4 ea)
         Nonce(36 8a 07 d4 93 10 db 6b d5 75 67 ce d3 44 e1 ec 12 fc 97 6d e9 ac 30 e8 e2 c0 35 57 62 1b d0 c8)
         MeasurementSummaryHash(00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00)
         OpaqueData()
         Signature(5c 3d 7c f2 15 d4 40 ff 07 28 61 d8 23 a9 82 18 0f c3 8b eb aa 83 80 4b 9c 99 ca 91 ab 26 17 18 48 88 88 df ca b4 8a e5 44 e5 d6 c3 ea 56 40 4d 74 e6 a3 73 36 52 b3 f9 e2 34 d1 b1 cd 96 eb 52)
      ......
      29 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x00(TotalNum))
      30 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (TotalMeasIndex=0x04)
      31 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x01)
      32 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
         MeasurementRecord(01 01 23 00 00 20 00 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01)
            MeasurementRecord_0(
            CommonHeader(Index=0x01, MeasSpec=0x01(DMTF), Size=0x0023)
            DmtfHeader(Type=0x00(ImmutableROM), Size=0x0020)
            Value(01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01)
            )
      33 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x02)
      34 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
         MeasurementRecord(02 01 23 00 01 20 00 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02)
            MeasurementRecord_0(
            CommonHeader(Index=0x02, MeasSpec=0x01(DMTF), Size=0x0023)
            DmtfHeader(Type=0x01(MutableFirmware), Size=0x0020)
            Value(02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02)
            )
      35 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x00(), MeasOp=0x03)
      36 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27)
         MeasurementRecord(03 01 23 00 02 20 00 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03)
            MeasurementRecord_0(
            CommonHeader(Index=0x03, MeasSpec=0x01(DMTF), Size=0x0023)
            DmtfHeader(Type=0x02(HardwareConfig), Size=0x0020)
            Value(03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03 03)
            )
      37 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe0) SPDM_GET_MEASUREMENTS (Attr=0x01(GenSig), MeasOp=0x04, SlotID=0x00)
         Nonce(08 ac 84 a2 8a 77 73 26 48 a7 e6 00 5d ba f6 36 cd 74 e6 4c 19 25 58 ad 11 2a c0 4d ea b6 18 8d)
      38 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x60) SPDM_MEASUREMENTS (NumOfBlocks=0x1, MeasRecordLen=0x27, SlotID=0x00)
         MeasurementRecord(04 01 23 00 03 20 00 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04)
            MeasurementRecord_0(
            CommonHeader(Index=0x04, MeasSpec=0x01(DMTF), Size=0x0023)
            DmtfHeader(Type=0x03(FirmwareConfig), Size=0x0020)
            Value(04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04)
            )
         Nonce(72 d9 12 cd 57 b8 09 6a 37 33 86 6d 06 7e b9 d0 25 88 ac 09 86 88 84 39 10 d8 04 a6 45 07 52 6b)
         OpaqueData()
         Signature(92 41 a7 63 7d 43 a8 07 c6 36 ba b0 07 24 d6 ce 5b e1 da 26 8c 20 37 4c 31 ab 4f b1 2a af 4c f7 5c bd ce de fa c2 c1 a5 03 d6 12 ed 80 80 6e ec 03 66 b0 fa 11 18 6f f4 77 f0 af 18 91 ba c5 eb)
      39 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe4) SPDM_KEY_EXCHANGE (HashType=0x01(TcbHash), SlotID=0x00, ReqSessionID=0xffff)
         RandomData(90 d3 d6 5f 3d a3 1b aa 4b ec 2d f0 47 d3 27 2e 46 e8 ef 03 7c 63 69 15 0a ad ea b1 18 23 f0 b1)
         ExchangeData(84 2d 46 42 7a d5 1a 1a 52 1b 54 57 24 ea ff 1c 1e 5a f0 48 16 33 f9 54 b3 d2 9d 19 74 0c 99 df 3c b4 d2 90 0d 99 f4 98 13 75 01 6b ee 30 1d 72 5e 28 12 7a 52 b3 a7 fc 7f 16 04 f7 73 3b 6f 7f)
         OpaqueData(46 54 4d 44 01 01 00 00 00 00 05 00 01 01 01 00 11 00 00 00)
            SecuredMessageOpaqueDataHeader(SpecId=0x444d5446(DMTF), Ver=0x01, TotalElem=0x01)
            SecuredMessageOpaqueElement_0(Id=0x00, Len=0x0005) Element(Ver=0x01, Id=0x01) SUPPORTED_VERSION (1.1.0.0)
      40 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x64) SPDM_KEY_EXCHANGE_RSP (Heart=0x00, RspSessionID=0xffff, MutAuth=0x03(Requested,WithEncap), SlotID=0x00)
         RandomData(9d b9 4a 9b 8a 4b d1 91 47 77 60 e5 8a 2e fa 1c 16 36 1b 54 e1 c1 f8 79 72 44 09 bc 8e 86 c5 41)
         ExchangeData(d2 1b 13 b9 58 3a b4 a4 3c 1a f9 0d 0f 0e f5 02 01 ae 7f be 0e c6 8e 11 5b a5 ea 14 0e 59 80 a1 a1 dc fa 11 d3 50 f7 8c 9a 4c 30 ec d8 4c 45 53 d2 9a 9f e2 21 00 06 0f 69 b0 42 92 c4 87 1a 0d)
         MeasurementSummaryHash(72 cd 6e 84 22 c4 07 fb 6d 09 86 90 f1 13 0b 7d ed 7e c2 f7 f5 e1 d3 0b d9 d5 21 f0 15 36 37 93)
         OpaqueData(46 54 4d 44 01 01 00 00 00 00 04 00 01 00 00 11)
            SecuredMessageOpaqueDataHeader(SpecId=0x444d5446(DMTF), Ver=0x01, TotalElem=0x01)
            SecuredMessageOpaqueElement_0(Id=0x00, Len=0x0004) Element(Ver=0x01, Id=0x00) VERSION_SELECTION (1.1.0.0)
         Signature(cf b8 e3 50 01 ee cc 2e d6 54 ef e4 1f 2d cd 77 2d 55 c5 22 69 6c a5 4f 81 8b 9a 9b 69 13 11 9b fd 5e 79 3e 39 a6 09 27 ba 0e a2 9c ee e9 e3 48 86 03 8a df cc 12 a9 ea f7 21 44 82 a9 ed 90 68)
      ......
      53 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe5) SPDM_FINISH (Attr=0x01 (SigIncl=1), SlotID=0x00)
         Signature(4c 89 04 a9 3d 44 36 fa a5 ed b9 f3 24 64 9a e5 a2 f0 f2 71 9f 40 7f 2b ee 52 a0 8d 1b 8b d2 aa 26 4f 22 9a 7d 98 b7 8e fa cb cb f4 a2 e4 6e d3 03 da df 31 29 69 4e 6c 65 07 42 85 b9 47 42 15 9b dc 69 0e 37 d9 12 88 c1 67 c7 45 99 ba b0 55 09 d2 c6 6a 4e 0b ef 57 4b eb 16 7a 27 8e 72 9f a8 aa 23 05 88 10 06 bf fa c5 b6 ad f4 1a 08 ad 61 b7 6c 7e 10 12 2a 54 ff ee 3e 53 ce 26 80 e5 88 f7 53 50 3e d7 f2 f5 30 19 f1 66 eb cd 05 85 10 4d 56 55 88 e7 f7 24 f0 38 0c 4c 8b e6 f7 fe f1 3c 2d 1a c1 61 cb 81 eb 86 58 40 18 70 f5 91 e1 1a 26 6e a4 39 db ae b5 7e da 43 88 00 7d 90 1f d0 45 ec ff 3e d4 ac 1d 94 ab bd b8 90 76 88 2f 28 c4 95 29 ac 61 9e 6b 37 14 c4 fe 2d 1c ee b2 e9 82 85 48 4f c4 cf 0a e4 0a e8 df e3 71 f9 98 ab 93 39 70 f5 f1 90 de 44 f5 63 40 43 c2 05)
         VerifyData(f0 27 cd b2 8b 7c a2 33 da 4f 67 9d a3 5d a0 ca 66 ac 60 8d f6 ae 45 7d 28 47 75 ab 12 6f 09 08)
      54 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x65) SPDM_FINISH_RSP ()
         VerifyData(04 20 b8 c9 99 8a 26 af dc 4c 7f ae 03 5d 0a 19 6b 28 ff a4 05 23 97 db d3 84 b0 1b 6c b2 9c 2f)
      55 (1608625474) MCTP(5) REQ->RSP SPDM(11, 0xe6) SPDM_PSK_EXCHANGE (HashType=0x01(TcbHash), ReqSessionID=0xfffe, PSKHint=5465737450736b48696e7400)
         Context(8c 17 60 b5 5a f3 41 f9 19 52 8c 20 cb 03 67 09 e8 6a 32 df f6 c9 be 89 5a be b9 41 6e 0d 6d 82 d3 a0 ab 28 09 cc 01 d3 3c d6 33 8c 61 b6 e9 ab 82 1a a6 f7 56 ae f9 10 15 9b f7 0a 8a 4d e8 5b)
         OpaqueData(46 54 4d 44 01 01 00 00 00 00 05 00 01 01 01 00 11 00 00 00)
            SecuredMessageOpaqueDataHeader(SpecId=0x444d5446(DMTF), Ver=0x01, TotalElem=0x01)
            SecuredMessageOpaqueElement_0(Id=0x00, Len=0x0005) Element(Ver=0x01, Id=0x01) SUPPORTED_VERSION (1.1.0.0)
      56 (1608625474) MCTP(5) RSP->REQ SPDM(11, 0x66) SPDM_PSK_EXCHANGE_RSP (Heart=0x00, RspSessionID=0xfffe)
         MeasurementSummaryHash(72 cd 6e 84 22 c4 07 fb 6d 09 86 90 f1 13 0b 7d ed 7e c2 f7 f5 e1 d3 0b d9 d5 21 f0 15 36 37 93)
         Context(00 17 9b 68 e5 ee c1 31 1b e2 6d de 42 1b ed 11 cb 5f cb c3 15 9b 06 7e d6 bf a3 cd bd cf 64 f2 56 37 d8 d6 2d 60 94 46 36 80 bf 5b 6c b6 d4 3a b9 56 a3 fe 16 82 99 f3 f3 fa 42 05 d9 34 0c 78)
         OpaqueData(46 54 4d 44 01 01 00 00 00 00 04 00 01 00 00 11)
            SecuredMessageOpaqueDataHeader(SpecId=0x444d5446(DMTF), Ver=0x01, TotalElem=0x01)
            SecuredMessageOpaqueElement_0(Id=0x00, Len=0x0004) Element(Ver=0x01, Id=0x00) VERSION_SELECTION (1.1.0.0)
         VerifyData(37 71 6b fa e9 da e4 82 f3 9c 05 8e d7 e8 9e fc 5f 2d 93 0c 70 49 6f b5 61 9c 66 40 ff 71 11 ce)
      57 (1608625474) MCTP(6) REQ->RSP SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0xe7) SPDM_PSK_FINISH ()
         VerifyData(d5 8f 55 97 8e 97 c6 f8 1a d5 0d 5f 9f da 6b 83 8e 15 5f 1b c4 0d df 7c 42 cb 79 24 89 b4 59 e0)
      58 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0000) MCTP(5) SPDM(11, 0x67) SPDM_PSK_FINISH_RSP ()
      ......
   </pre>

   Below is hex dump:

   <pre>
      ......
      1 (1608625474) MCTP(5) REQ->RSP SPDM(10, 0x84) SPDM_GET_VERSION ()
         SPDM Message:
            0000: 10 84 00 00
      ......
      82 (1608625474) MCTP(6) RSP->REQ SecuredSPDM(0xfffefffe, Seq=0x0002) MCTP(5) SPDM(11, 0x6c) SPDM_END_SESSION_ACK ()
         SPDM Message:
            0000: 11 6c 00 00
         SecuredSPDM Message:
            0000: fe ff fe ff 30 00 05 00 05 11 6c 00 00 da 91 1a 1f 1e 2c 57 84 e0 59 b3 00 f9 9d 76 00 00 00 00
            0020: 46 00 00 00 00 00 2c 44 0f 0a b2 32 f8 92 0f 08 e8 90 14 30 bf 8e
   </pre>

   NOTE: Not all commands and fields are dumped so far. Please file issue or submit patch for them if you want to see something interesting.
