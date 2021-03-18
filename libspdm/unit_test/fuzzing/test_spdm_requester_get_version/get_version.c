/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_requester_lib_internal.h>

uintn
get_max_buffer_size (
  void
  )
{
  return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

return_status
spdm_device_send_message (
  IN     void                    *spdm_context,
  IN     uintn                   request_size,
  IN     void                    *request,
  IN     uint64                  timeout
  )
{
  return RETURN_SUCCESS;
}

return_status
spdm_device_receive_message (
  IN     void                    *spdm_context,
  IN OUT uintn                   *response_size,
  IN OUT void                    *response,
  IN     uint64                  timeout
  )
{
  spdm_test_context_t       *spdm_test_context;

  spdm_test_context = get_spdm_test_context ();
  *response_size = spdm_test_context->test_buffer_size;
  copy_mem (response, spdm_test_context->test_buffer, spdm_test_context->test_buffer_size);

  return RETURN_SUCCESS;
}

void test_spdm_requester_get_version (void **State) {
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;

  spdm_test_context = *State;
  spdm_context = spdm_test_context->spdm_context;

  spdm_get_version (spdm_context);
}

spdm_test_context_t       m_spdm_requester_get_version_test_context = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  TRUE,
  spdm_device_send_message,
  spdm_device_receive_message,
};

void
run_test_harness(
  IN void  *test_buffer,
  IN uintn test_buffer_size
  )
{
  void  *State;

  setup_spdm_test_context (&m_spdm_requester_get_version_test_context);

  m_spdm_requester_get_version_test_context.test_buffer = test_buffer;
  m_spdm_requester_get_version_test_context.test_buffer_size = test_buffer_size;

  spdm_unit_test_group_setup (&State);

  test_spdm_requester_get_version (&State);

  spdm_unit_test_group_teardown (&State);
}

