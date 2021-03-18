/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_unit_fuzzing.h"
#include "toolchain_harness.h"
#include <spdm_responder_lib_internal.h>

uintn
get_max_buffer_size (
  void
  )
{
  return MAX_SPDM_MESSAGE_BUFFER_SIZE;
}

void test_spdm_responder_version(void **State) {
  spdm_test_context_t    *spdm_test_context;
  spdm_context_t  *spdm_context;
  uintn                response_size;
  uint8                response[MAX_SPDM_MESSAGE_BUFFER_SIZE];

  spdm_test_context = *State;
  spdm_context = spdm_test_context->spdm_context;

  response_size = sizeof(response);
  spdm_get_response_version (spdm_context, spdm_test_context->test_buffer_size, spdm_test_context->test_buffer, &response_size, response);
}

spdm_test_context_t       m_spdm_responder_version_test_context = {
  SPDM_TEST_CONTEXT_SIGNATURE,
  FALSE,
};

void
run_test_harness(
  IN void  *test_buffer,
  IN uintn test_buffer_size
  )
{
  void  *State;

  setup_spdm_test_context (&m_spdm_responder_version_test_context);

  m_spdm_responder_version_test_context.test_buffer = test_buffer;
  m_spdm_responder_version_test_context.test_buffer_size = test_buffer_size;

  spdm_unit_test_group_setup (&State);

  test_spdm_responder_version (&State);

  spdm_unit_test_group_teardown (&State);
}

