/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_unit_test.h"
#include <spdm_requester_lib_internal.h>

int spdm_requester_get_version_test_main (void);
int spdm_requester_get_capabilities_test_main (void);
int spdm_requester_negotiate_algorithms_test_main (void);
int spdm_requester_get_digests_test_main (void);
int spdm_requester_get_certificate_test_main (void);
int spdm_requester_challenge_test_main (void);
int spdm_requester_get_measurements_test_main (void);
int spdm_requester_key_exchange_test_main (void);
int spdm_requester_finish_test_main (void);
int spdm_requester_psk_exchange_test_main (void);
int spdm_requester_psk_finish_test_main (void);
int spdm_requester_heartbeat_test_main (void);
int spdm_requester_end_session_test_main (void);

int main(void) {
  spdm_requester_get_version_test_main();

  spdm_requester_get_capabilities_test_main();

  spdm_requester_negotiate_algorithms_test_main();

  spdm_requester_get_digests_test_main();

  spdm_requester_get_certificate_test_main();

  spdm_requester_challenge_test_main();

  spdm_requester_get_measurements_test_main();

  spdm_requester_key_exchange_test_main();

  spdm_requester_finish_test_main();

  spdm_requester_psk_exchange_test_main();

  spdm_requester_psk_finish_test_main();

  spdm_requester_heartbeat_test_main();

  spdm_requester_end_session_test_main();
  return 0;
}
