# SPDM OsTest Tool

This document describes SpdmRequesterTest and SpdmResponderTest tool. It can be used to test the SPDM communication in the OS.

## Spdm OS tool user guide

   <pre>
      SpdmRequesterTest|SpdmResponderTest [--trans MCTP|PCI_DOE]
         [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--measurement_hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512]
         [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521]
         [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1]
         [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305]
         [--key_schedule HMAC_HASH]
         [--pcap <PcapFileName>]

      NOTE:
         [--trans] is used to select transport layer message. By default, MCTP is used.

         [--hash] is hash algorithm. By default, SHA_256 is used.
         [--measurement_hash] is measurement hash algorithm. By default, SHA_256 is used.
         [--asym] is asym algorithm. By default, ECDSA_P256 is used.
         [--req_asym] is requester asym algorithm. By default, RSASSA_2048 is used.
         [--dhe] is DHE algorithm. By default, SECP_256_R1 is used.
         [--aead] is AEAD algorithm. By default, AES_256_GCM is used.
         [--key_schedule] is key schedule algorithm. By default, HMAC_HASH is used.

         [--pcap] is used to generate PCAP dump file for offline analysis.
   </pre>

   Take SpdmRequesterTest or SpdmResponderTest as an example, a user may use `SpdmRequesterTest --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderTest --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   To test PCI_DOE, a user may use `SpdmRequesterTest --trans PCI_DOE --pcap SpdmRequester.pcap > SpdmRequester.log` or `SpdmResponderTest  --trans PCI_DOE --pcap SpdmResponder.pcap > SpdmResponder.log` to get the PCAP file and the log file.

   [SpdmDump](https://github.com/jyao1/openspdm/blob/master/Doc/SpdmDump.md) tool can be used to parse the pcap file for offline analysis.
