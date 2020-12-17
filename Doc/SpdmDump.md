# SPDM Dump Tool

This document describes SpdmDump tool. It can be used to parse the SPDM message in a dump file offline.

## SPDM message dump file format

   We use [pcap](https://www.tcpdump.org/manpages/pcap-savefile.5.txt) file format.

   The packet must include the transport layer. We add below extension for [LinkType](https://www.tcpdump.org/linktypes.html).
   
   ```
   #define LINKTYPE_MCTP      290  // 0x0122
   #define LINKTYPE_PCI_DOE   291  // 0x0123
   ```

## SPDM requester user guide

   Use "SpdmDump -r <pcap_file>" to dump the SPDM message. You may see something like:

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
      7 (1608173380) PCI_DOE(1, 1) SPDM(11, 0x81) REQ->RSP SPDM_GET_DIGESTS
      8 (1608173380) PCI_DOE(1, 1) SPDM(11, 0x01) RSP->REQ SPDM_DIGESTS
      ......
   </pre>

