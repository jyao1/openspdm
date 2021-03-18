/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "spdm_dump.h"

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void
dump_hex_str (
  IN uint8  *data,
  IN uintn  size
  )
{
  uintn  index;

  for (index = 0; index < size; index++) {
    printf ("%02x", data[index]);
  }
}

/**
  This function dump raw data.

  @param  data  raw data
  @param  size  raw data size
**/
void
dump_data (
  IN uint8  *data,
  IN uintn  size
  )
{
  uintn  index;

  for (index = 0; index < size; index++) {
    if (index != 0) {
      printf (" ");
    }
    printf ("%02x", data[index]);
  }
}

/**
  This function dump raw data with colume format.

  @param  data  raw data
  @param  size  raw data size
**/
void
dump_hex (
  IN uint8  *data,
  IN uintn  size
  )
{
  uint32  index;
  uintn   count;
  uintn   left;

#define COLUME_SIZE  (16 * 2)

  count = size / COLUME_SIZE;
  left  = size % COLUME_SIZE;
  for (index = 0; index < count; index++) {
    printf ("    %04x: ", index * COLUME_SIZE);
    dump_data (data + index * COLUME_SIZE, COLUME_SIZE);
    printf ("\n");
  }

  if (left != 0) {
    printf ("    %04x: ", index * COLUME_SIZE);
    dump_data (data + index * COLUME_SIZE, left);
    printf ("\n");
  }
}

static
boolean
char_to_byte (
  IN  char8  ch,
  OUT uint8  *data
  )
{
  if (ch >= '0' && ch <= '9') {
    *data = ch - '0';
    return TRUE;
  }
  if (ch >= 'a' && ch <= 'f') {
    *data = ch - 'a' + 0xa;
    return TRUE;
  }
  if (ch >= 'A' && ch <= 'F') {
    *data = ch - 'A' + 0xA;
    return TRUE;
  }
  printf ("hex_string error - invalid char '%c'\n", ch);
  return FALSE;
}

static
boolean
one_byte_string_to_buffer (
  IN  char8   one_byte_string[2],
  OUT uint8   *buffer
  )
{
  uint8 data_h;
  uint8 data_l;

  if (!char_to_byte (one_byte_string[0], &data_h)) {
    return FALSE;
  }
  if (!char_to_byte (one_byte_string[1], &data_l)) {
    return FALSE;
  }

  *buffer = (data_h << 4) | data_l;
  return TRUE;
}

boolean
hex_string_to_buffer (
  IN  char8   *hex_string,
  OUT void    **buffer,
  OUT uintn   *buffer_size
  )
{
  uintn   str_len;
  uintn   index;

  str_len = strlen (hex_string);
  if ((str_len & 0x1) != 0) {
    printf ("hex_string error - strlen (%d) is not even\n", (uint32)str_len);
    return FALSE;
  }
  *buffer_size = str_len / 2;
  *buffer = (void *)malloc(*buffer_size);
  if (*buffer == NULL) {
    printf ("memory out of resource\n");
    return FALSE;
  }

  for (index = 0; index < str_len / 2; index++) {
    if (!one_byte_string_to_buffer (hex_string + index * 2, (uint8 *)*buffer + index)) {
      return FALSE;
    }
  }

  return TRUE;
}

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

boolean
write_output_file (
  IN char8   *file_name,
  IN void    *file_data,
  IN uintn   file_size
  )
{
  FILE                        *fp_out;

  if ((fp_out = fopen (file_name, "w+b")) == NULL) {
    printf ("Unable to open file %s\n", file_name);
    return FALSE;
  }

  if ((fwrite (file_data, 1, file_size, fp_out)) != file_size) {
    printf ("Write output file error %s\n", file_name);
    fclose (fp_out);
    return FALSE;
  }

  fclose (fp_out);

  return TRUE;
}

boolean
open_output_file (
  IN char8   *file_name
  )
{
  FILE                        *fp_out;

  if ((fp_out = fopen (file_name, "w+b")) == NULL) {
    printf ("Unable to open file %s\n", file_name);
    return FALSE;
  }

  fclose (fp_out);

  return TRUE;
}
