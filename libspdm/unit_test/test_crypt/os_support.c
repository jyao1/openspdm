/** @file  

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "test_crypt.h"

#include <stdio.h>

boolean
read_input_file (
  IN char8    *file_name,
  OUT void    **file_data,
  OUT uintn   *file_size
  )
{
  FILE                        *fp_in;
  uintn                       temp_result;

  if ((fp_in = fopen (file_name, "rb")) == NULL) {
    printf ("Unable to open file %s\n", file_name);
    *file_data = NULL;
    return FALSE;
  }

  fseek (fp_in, 0, SEEK_END);
  *file_size = ftell (fp_in);

  *file_data = (void *) malloc (*file_size);
  if (NULL == *file_data) {
    printf ("No sufficient memory to allocate %s\n", file_name);
    fclose (fp_in);
    return FALSE;
  }

  fseek (fp_in, 0, SEEK_SET);
  temp_result = fread (*file_data, 1, *file_size, fp_in);
  if (temp_result != *file_size) {
    printf ("Read input file error %s", file_name);
    free ((void *)*file_data);
    fclose (fp_in);
    return FALSE;
  }

  fclose (fp_in);

  return TRUE;
}
