/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_unit_test.h"
#include <spdm_responder_lib_internal.h>

int spdm_responder_version_test_main (void);
int spdm_responder_capabilities_test_main (void);
int spdm_responder_algorithms_test_main (void);
int spdm_responder_digests_test_main (void);
int spdm_responder_certificate_test_main (void);
int spdm_responder_challenge_auth_test_main (void);
int spdm_responder_measurements_test_main (void);
int spdm_responder_key_exchange_test_main (void);
int spdm_responder_finish_test_main (void);
int spdm_responder_psk_exchange_test_main (void);
int spdm_responder_psk_finish_test_main (void);
int spdm_responder_heartbeat_test_main (void);
int spdm_responder_end_session_test_main (void);

int main(void) {
  spdm_responder_version_test_main ();

  spdm_responder_capabilities_test_main ();

  spdm_responder_algorithms_test_main ();

  spdm_responder_digests_test_main ();

  spdm_responder_certificate_test_main ();

  spdm_responder_challenge_auth_test_main ();

  spdm_responder_measurements_test_main ();

  spdm_responder_key_exchange_test_main ();

  spdm_responder_finish_test_main();

  spdm_responder_psk_exchange_test_main();

  spdm_responder_psk_finish_test_main();

  spdm_responder_heartbeat_test_main();

  spdm_responder_end_session_test_main();
  return 0;
}
