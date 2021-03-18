/** @file
  Provides random number generator services.

Copyright (c) 2015, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __RNG_LIB_H__
#define __RNG_LIB_H__

/**
  Generates a 64-bit random number.

  if rand is NULL, then ASSERT().

  @param[out] rand_data     buffer pointer to store the 64-bit random value.

  @retval TRUE         Random number generated successfully.
  @retval FALSE        Failed to generate the random number.

**/
boolean
get_random_number_64 (
  OUT     uint64                    *rand_data
  );

#endif  // __RNG_LIB_H__
