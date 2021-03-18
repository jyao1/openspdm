/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

pcap_global_header_t  m_pcap_global_header;
FILE                *m_pcap_file;
void                *m_pcap_packet_data_buffer;

dispatch_table_entry_t m_pcap_dispatch[] = {
  {LINKTYPE_MCTP,    "MCTP",    dump_mctp_packet},
  {LINKTYPE_PCI_DOE, "PCI_DOE", dump_pci_doe_packet},
};

char8 *
data_link_type_to_string (
  IN uint32  data_link_type
  )
{
  switch (data_link_type) {
  case LINKTYPE_MCTP:
    return "MCTP";
  case LINKTYPE_PCI_DOE:
    return "PCI_DOE";
  default:
    return "<Unknown>";
  }
}

uint32
get_max_packet_length (
  void
  )
{
  return m_pcap_global_header.snap_len;
}

uint32
get_data_link_type (
  void
  )
{
  return m_pcap_global_header.network;
}

void
dump_pcap_global_header (
  IN pcap_global_header_t  *pcap_global_header
  )
{
  printf (
    "PcapFile: Magic - '%x', version%d.%d, DataLink - %d (%s), MaxPacketSize - %d\n",
    pcap_global_header->magic_number,
    pcap_global_header->version_major,
    pcap_global_header->version_minor,
    pcap_global_header->network,
    data_link_type_to_string (pcap_global_header->network),
    pcap_global_header->snap_len
    );
}

boolean
open_pcap_packet_file (
  IN char8  *pcap_file_name
  )
{

  if (pcap_file_name == NULL) {
    return FALSE;
  }

  if ((m_pcap_file = fopen (pcap_file_name, "rb")) == NULL) {
    printf ("!!!Unable to open pcap file %s!!!\n", pcap_file_name);
    return FALSE;
  }

  if (fread (&m_pcap_global_header, 1, sizeof(pcap_global_header_t), m_pcap_file) != sizeof(pcap_global_header_t)) {
    printf ("!!!Unable to read the pcap global header!!!\n");
    return FALSE;
  }

  if ((m_pcap_global_header.magic_number != PCAP_GLOBAL_HEADER_MAGIC) &&
      (m_pcap_global_header.magic_number != PCAP_GLOBAL_HEADER_MAGIC_SWAPPED) &&
      (m_pcap_global_header.magic_number != PCAP_GLOBAL_HEADER_MAGIC_NANO) &&
      (m_pcap_global_header.magic_number != PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED) ) {
    printf ("!!!pcap file magic invalid '%x'!!!\n", m_pcap_global_header.magic_number);
    return FALSE;
  }
  
  dump_pcap_global_header (&m_pcap_global_header);

  if (m_pcap_global_header.snap_len == 0) {
    return FALSE;
  }

  m_pcap_packet_data_buffer = (void *)malloc (m_pcap_global_header.snap_len);
  if (m_pcap_packet_data_buffer == NULL) {
    printf ("!!!memory out of resources!!!\n");
    return FALSE;
  }

  return TRUE;
}

void
close_pcap_packet_file (
  void
  )
{
  if (m_pcap_file != NULL) {
    fclose (m_pcap_file);
    m_pcap_file = NULL;
  }
  if (m_pcap_packet_data_buffer != NULL) {
    free (m_pcap_packet_data_buffer);
    m_pcap_packet_data_buffer = NULL;
  }
}

void
dump_pcap_packet_header (
  IN uintn               index,
  IN pcap_packet_header_t  *pcap_packet_header
  )
{
  printf (
    "%d (%d) ",
    (uint32)index,
    pcap_packet_header->ts_sec
    );
}

void
dump_pcap_packet (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  dump_dispatch_message (m_pcap_dispatch, ARRAY_SIZE(m_pcap_dispatch), m_pcap_global_header.network, buffer, buffer_size);
}

void
dump_pcap (
  void
  )
{
  pcap_packet_header_t  pcap_packet_header;
  uintn               index;

  index = 1;

  while (TRUE) {
    if (fread (&pcap_packet_header, 1, sizeof(pcap_packet_header_t), m_pcap_file) != sizeof(pcap_packet_header_t)) {
      return ;
    }
    dump_pcap_packet_header (index++, &pcap_packet_header);
    if (pcap_packet_header.incl_len == 0) {
      return ;
    }
    if (fread (m_pcap_packet_data_buffer, 1, pcap_packet_header.incl_len, m_pcap_file) != pcap_packet_header.incl_len) {
      return ;
    }
    dump_pcap_packet (m_pcap_packet_data_buffer, pcap_packet_header.incl_len);
  }
}

