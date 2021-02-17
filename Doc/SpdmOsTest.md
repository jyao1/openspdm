# SPDM OsTest Tool

This document describes SpdmRequesterEmu and SpdmResponderEmu tool. It can be used to test the SPDM communication in the OS.

## Spdm OS tool user guide

   <pre>
      SpdmRequesterEmu|SpdmResponderEmu [--trans MCTP|PCI_DOE]
         [--ver 1.0|1.1]
         [--cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID]
         [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]
         [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]
         [--key_schedule HMAC_HASH]
         [--mut_auth BASIC|ENCAP|DIGESTS]
         [--meas_sum NO|TCB|ALL]
         [--meas_op ONE_BY_ONE|ALL]
         [--slot_id <0~7|0xFF>]
         [--slot_count <1~8>]
         [--pcap <PcapFileName>]

      NOTE:
         [--trans] is used to select transport layer message. By default, MCTP is used.
         [--ver] is version. By default, 1.1 is used.
         [--cap] is capability flags. Multiple flags can be set together. Please use ',' for them.
                 By default, CERT,CHAL,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Requester.
                 By default, CERT,CHAL,MEAS_SIG,MEAS_FRESH,ENCRYPT,MAC,MUT_AUTH,KEY_EX,PSK_WITH_CONTEXT,ENCAP,HBEAT,KEY_UPD,HANDSHAKE_IN_CLEAR is used for Responder.
         [--hash] is hash algorithm. By default, SHA_384,SHA_256 is used.
         [--meas_hash] is measurement hash algorithm. By default, SHA_512,SHA_384,SHA_256 is used.
         [--asym] is asym algorithm. By default, ECDSA_P384,ECDSA_P256 is used.
         [--req_asym] is requester asym algorithm. By default, RSAPSS_3072,RSAPSS_2048,RSASSA_3072,RSASSA_2048 is used.
         [--dhe] is DHE algorithm. By default, SECP_384_R1,SECP_256_R1,FFDHE_3072,FFDHE_2048 is used.
         [--aead] is AEAD algorithm. By default, AES_256_GCM,CHACHA20_POLY1305 is used.
         [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.
                 Above algorithms also support multiple flags. Please use ',' for them.
                 SHA3 is not supported so far.
         [--mut_auth] is the mutual authentication policy. BASIC is used in CHALLENGE_AUTH, ENCAP or DIGESTS is used in KEY_EXCHANGE_RSP. By default, BASIC,ENCAP is used.
         [--meas_sum] is the measurment summary hash type in CHALLENGE_AUTH, KEY_EXCHANGE_RSP and PSK_EXCHANGE_RSP. By default, ALL is used.
         [--meas_op] is the measurement operation in GET_MEASUREMEMT. By default, ONE_BY_ONE is used.
         [--slot_id] is to select the peer slot ID in GET_MEASUREMENT, CHALLENGE_AUTH, KEY_EXCHANGE and FINISH. By default, 0 is used.
                 0xFF can be used to indicate provisioned certificate chain. No GET_CERTIFICATE is needed.
         [--slot_count] is to select the local slot count. By default, 3 is used.
         [--pcap] is used to generate PCAP dump file for offline analysis.
   </pre>

   Take SpdmRequesterEmu or SpdmResponderEmu as an example, a user may use `SpdmRequesterEmu --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderEmu --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   To test PCI_DOE, a user may use `SpdmRequesterEmu --trans PCI_DOE --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderEmu  --trans PCI_DOE --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   [SpdmDump](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmDump.md) tool can be used to parse the pcap file for offline analysis.

   NOTE: Not all combination is supported. Please file issue or submit patch for them if you find something is not expected.
