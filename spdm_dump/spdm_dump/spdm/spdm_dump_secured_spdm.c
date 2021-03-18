/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

extern void               *m_spdm_dec_message_buffer;
extern void               *m_spdm_context;
extern void               *m_current_session_info;
extern uint32             m_current_session_id;
extern boolean            m_decrypted;

void
dump_spdm_opaque_version_selection (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  secured_message_opaque_element_version_selection_t *version_selection;

  if (buffer_size < sizeof(secured_message_opaque_element_version_selection_t)) {
    return ;
  }

  version_selection = buffer;

  printf ("VERSION_SELECTION ");
  
  printf ("(%d.%d.%d.%d) ",
    version_selection->selected_version.major_version,
    version_selection->selected_version.minor_version,
    version_selection->selected_version.update_version_number,
    version_selection->selected_version.alpha
    );
}

void
dump_spdm_opaque_supported_version (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  secured_message_opaque_element_supported_version_t *supported_version;
  spdm_version_number_t                              *spdm_version_number;
  uintn                                            index;

  if (buffer_size < sizeof(secured_message_opaque_element_supported_version_t)) {
    return ;
  }

  supported_version = buffer;
  if (buffer_size < sizeof(secured_message_opaque_element_supported_version_t) + supported_version->version_count * sizeof(spdm_version_number_t)) {
    return ;
  }

  printf ("SUPPORTED_VERSION ");

  spdm_version_number = (void *)(supported_version + 1);
  printf ("(");
  for (index = 0; index < supported_version->version_count; index ++) {
    if (index != 0) {
      printf (", ");
    }
    printf ("%d.%d.%d.%d",
      spdm_version_number[index].major_version,
      spdm_version_number[index].minor_version,
      spdm_version_number[index].update_version_number,
      spdm_version_number[index].alpha
      );
    printf (") ");
  }
}

dispatch_table_entry_t m_spdm_opaque_dispatch[] = {
  {SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,  "VERSION_SELECTION",  dump_spdm_opaque_version_selection},
  {SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,  "SUPPORTED_VERSION",  dump_spdm_opaque_supported_version},
};

void
dump_spdm_opaque_data (
  IN uint8    *opaque_data,
  IN uint16   opaque_length
  )
{
  secured_message_general_opaque_data_table_header_t  *secured_message_opaque_data_table;
  secured_message_opaque_element_table_header_t       *secured_message_element_table;
  secured_message_opaque_element_header_t             *secured_message_element;
  uintn                                             end_of_element_table;
  uintn                                             end_of_opaque_data;
  uintn                                             index;
  char8                                             *ch;

  end_of_opaque_data = (uintn)opaque_data + opaque_length;

  if (opaque_length < sizeof(secured_message_general_opaque_data_table_header_t)) {
    return ;
  }

  secured_message_opaque_data_table = (void *)opaque_data;
  if (secured_message_opaque_data_table->spec_id != SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) {
    return ;
  }

  ch = (void *)&secured_message_opaque_data_table->spec_id;
  printf ("\n      SecuredMessageOpaqueDataHeader(spec_id=0x%08x(%c%c%c%c), Ver=0x%02x, TotalElem=0x%02x)",
    secured_message_opaque_data_table->spec_id,
    ch[3], ch[2], ch[1], ch[0],
    secured_message_opaque_data_table->opaque_version,
    secured_message_opaque_data_table->total_elements
    );
  
  secured_message_element_table = (void *)(secured_message_opaque_data_table + 1);
  for (index = 0; index < secured_message_opaque_data_table->total_elements; index++) {
    if ((uintn)secured_message_element_table + sizeof(secured_message_opaque_element_table_header_t) > end_of_opaque_data) {
      break;
    }
    if (secured_message_element_table->id != SPDM_REGISTRY_ID_DMTF) {
      break;
    }
    if (secured_message_element_table->vendor_len != 0) {
      break;
    }
    end_of_element_table = (uintn)secured_message_element_table + sizeof(secured_message_opaque_element_table_header_t) + secured_message_element_table->opaque_element_data_len;
    if (end_of_element_table > end_of_opaque_data) {
      break;
    }
    printf ("\n      SecuredMessageOpaqueElement_%d(id=0x%02x, len=0x%04x) ",
      (uint32)index,
      secured_message_element_table->id,
      secured_message_element_table->opaque_element_data_len
      );

    if (secured_message_element_table->opaque_element_data_len < sizeof(secured_message_opaque_element_header_t)) {
      break;
    }
    secured_message_element = (void *)(secured_message_element_table + 1);
    printf ("Element(Ver=0x%02x, id=0x%02x) ", secured_message_element->sm_data_version, secured_message_element->sm_data_id);

    dump_dispatch_message (m_spdm_opaque_dispatch, ARRAY_SIZE(m_spdm_opaque_dispatch), secured_message_element->sm_data_id, (uint8 *)secured_message_element, secured_message_element_table->opaque_element_data_len);

    secured_message_element_table = (void *)end_of_element_table;
  }
}

dispatch_table_entry_t m_secured_spdm_dispatch[] = {
  {LINKTYPE_MCTP,    "", dump_mctp_message},
  {LINKTYPE_PCI_DOE, "", dump_spdm_message},
};

void
dump_secured_spdm_message (
  IN void    *buffer,
  IN uintn   buffer_size
  )
{
  spdm_secured_message_a_data_header1_t *record_header1;
  uint16                              sequence_num;
  uintn                               sequence_num_size;
  return_status                       status;
  uintn                               message_size;
  static boolean                      is_requester = FALSE;
  uint32                              data_link_type;
  spdm_secured_message_callbacks_t      spdm_secured_message_callbacks_t;
  void                                *secured_message_context;

  data_link_type = get_data_link_type();
  switch (data_link_type) {
  case LINKTYPE_MCTP:
    sequence_num_size = sizeof(uint16);
    spdm_secured_message_callbacks_t.version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks_t.get_sequence_number = spdm_mctp_get_sequence_number;
    spdm_secured_message_callbacks_t.get_max_random_number_count = spdm_mctp_get_max_random_number_count;
    break;
  case LINKTYPE_PCI_DOE:
    sequence_num_size = 0;
    spdm_secured_message_callbacks_t.version = SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
    spdm_secured_message_callbacks_t.get_sequence_number = spdm_pci_doe_get_sequence_number;
    spdm_secured_message_callbacks_t.get_max_random_number_count = spdm_pci_doe_get_max_random_number_count;
    break;
  default:
    ASSERT (FALSE);
    printf ("<UnknownTransportLayer> ");
    printf ("\n");
    return ;
  }

  if (buffer_size < sizeof(spdm_secured_message_a_data_header1_t) + sequence_num_size + sizeof(spdm_secured_message_a_data_header2_t)) {
    printf ("\n");
    return ;
  }

  is_requester = (boolean)(!is_requester);

  record_header1 = buffer;
  sequence_num = 0;
  if (data_link_type == LINKTYPE_MCTP) {
    sequence_num = *(uint16 *)(record_header1 + 1);
  }

  m_current_session_info = spdm_get_session_info_via_session_id (m_spdm_context, record_header1->session_id);
  m_current_session_id = record_header1->session_id;
  status = RETURN_UNSUPPORTED;
  if (m_current_session_info != NULL) {
    secured_message_context = spdm_get_secured_message_context_via_session_id (m_spdm_context, record_header1->session_id);
    if (secured_message_context != NULL) {
      message_size = get_max_packet_length();
      status = spdm_decode_secured_message (
                secured_message_context,
                record_header1->session_id,
                is_requester,
                buffer_size,
                buffer,
                &message_size,
                m_spdm_dec_message_buffer,
                &spdm_secured_message_callbacks_t
                );
      if (RETURN_ERROR(status)) {
        //
        // Try other direction, because a responder might initiate a message in Session.
        //
        status = spdm_decode_secured_message (
                  secured_message_context,
                  record_header1->session_id,
                  !is_requester,
                  buffer_size,
                  buffer,
                  &message_size,
                  m_spdm_dec_message_buffer,
                  &spdm_secured_message_callbacks_t
                  );
        if (!RETURN_ERROR(status)) {
          is_requester = !is_requester;
        }
      }
    }
  }

  if (!RETURN_ERROR(status)) {
    if (is_requester) {
      printf ("REQ->RSP ");
    } else {
      printf ("RSP->REQ ");
    }
    printf ("SecuredSPDM(0x%08x", record_header1->session_id);
    if (data_link_type == LINKTYPE_MCTP) {
      printf (", Seq=0x%04x", sequence_num);
    }
    printf (") ");

    m_decrypted = TRUE;
    dump_dispatch_message (m_secured_spdm_dispatch, ARRAY_SIZE(m_secured_spdm_dispatch), get_data_link_type(), m_spdm_dec_message_buffer, message_size);
    m_decrypted = FALSE;
  } else {
    printf ("(?)->(?) ");
    printf ("SecuredSPDM(0x%08x", record_header1->session_id);
    if (data_link_type == LINKTYPE_MCTP) {
      printf (", Seq=0x%04x", sequence_num);
    }
    printf (") ");
    printf ("<Unknown> ");
    printf ("\n");
  }

  if (m_param_dump_hex) {
    printf ("  SecuredSPDM message:\n");
    dump_hex (buffer, buffer_size);
  }
}
