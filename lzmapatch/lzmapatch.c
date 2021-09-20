/*!

   @file lzmapatch/lzmapatch.c

   @brief Command-line executable to apply an LZMA2 "diff" stream to
          transform an "old" file into a "new" one.

   @author Daniel Martin

   @copyright Copyright 2021 CrowdStrike, Inc.

*/
/*
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* I have no desire to use fopen_s for such a tiny utility */
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "minlzlib/minlzlib.h"

#define MAX_ALLOWED_FILE_SIZE (3ULL << 30)

/* Functions pulled from the sha256 library in the 7-Zip SDK */
#define SHA256_DIGEST_SIZE 32

typedef struct
{
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[64];
} CSha256;

void Sha256_Init(CSha256 *p);
void Sha256_Update(CSha256 *p, const uint8_t *data, size_t size);
void Sha256_Final(CSha256 *p, uint8_t *digest);

void print_sha256(const uint8_t *data, size_t size)
{
    CSha256 shaHolder;
    uint8_t digest[SHA256_DIGEST_SIZE];
    int i;

    Sha256_Init(&shaHolder);
    Sha256_Update(&shaHolder, data, size);
    Sha256_Final(&shaHolder, digest);

    for (i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        printf("%02x", digest[i]);
    }
}

int main(int argc, char *argv[])
{
    uint32_t new_file_size;
    size_t new_file_written;
    size_t old_file_size;
    uint32_t old_file_size32;
    size_t diff_file_size;
    size_t diff_file_read;
    size_t old_file_read;
    FILE *diff_file = NULL;
    FILE *old_file = NULL;
    FILE *new_file = NULL;
    uint8_t *input_buffer = NULL;
    uint8_t *output_buffer = NULL;
    int retval = 0;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s diff_file old_file new_output_file\n",
                argv[0]);
        retval = 2;
        goto Cleanup;
    }

    diff_file = fopen(argv[1], "rb");
    if (diff_file == NULL)
    {
        perror(argv[1]);
        retval = 1;
        goto Cleanup;
    }
    fseek(diff_file, 0, SEEK_END);
    diff_file_size = (size_t)ftell(diff_file);
    fseek(diff_file, 0, SEEK_SET);
    input_buffer = malloc(diff_file_size);
    if (input_buffer == NULL)
    {
        fprintf(stderr, "diff file malloc error");
        retval = 1;
        goto Cleanup;
    }
    diff_file_read = fread(input_buffer, 1, diff_file_size, diff_file);
    if (diff_file_read != diff_file_size)
    {
        fprintf(stderr, "File read failed (%zd vs %zd bytes)\n",
                diff_file_read, diff_file_size);
        retval = 1;
        goto Cleanup;
    }
    fclose(diff_file);
    diff_file = NULL;

    BfInitialize(input_buffer, (uint32_t)diff_file_size);
    DtInitialize(NULL, 1000, 0);

    if (! Lz2DecodeStream(&new_file_size, true))
    {
        fprintf(stderr, "Error finding new file size\n");
        retval = 1;
        goto Cleanup;
    }

    old_file = fopen(argv[2], "rb");
    if (old_file == NULL)
    {
        perror(argv[2]);
        retval = 1;
        goto Cleanup;
    }
    fseek(old_file, 0, SEEK_END);
    old_file_size = (size_t)ftell(old_file);
    fseek(old_file, 0, SEEK_SET);
    if (old_file_size >= MAX_ALLOWED_FILE_SIZE)
    {
        fprintf(stderr, "Error: old file too large\n");
        retval = 1;
        goto Cleanup;
    }

    output_buffer = malloc(old_file_size + new_file_size);
    if (output_buffer == NULL)
    {
        fprintf(stderr, "output buff malloc error");
        retval = 1;
        goto Cleanup;
    }
    old_file_read = fread(output_buffer, 1, old_file_size, old_file);
    if (old_file_read != old_file_size)
    {
        fprintf(stderr, "File read failed (%zd vs %zd bytes)\n",
                old_file_read, old_file_size);
        retval = 1;
        goto Cleanup;
    }
    fclose(old_file);
    old_file = NULL;
    old_file_size32 = (uint32_t)old_file_size;
    BfInitialize(input_buffer, (uint32_t)diff_file_size);
    DtInitialize(
        output_buffer, old_file_size32 + new_file_size, old_file_size32);
    if (! Lz2DecodeStream(&new_file_size, false))
    {
        fprintf(stderr, "Error decoding stream\n");
        retval = 1;
        goto Cleanup;
    }

    printf("New file size: %d\n", new_file_size);
    printf("New file sha256: ");
    print_sha256(output_buffer + old_file_size, new_file_size);
    printf("\n");

    new_file = fopen(argv[3], "wb");
    if (new_file == NULL)
    {
        perror(argv[3]);
        retval = 1;
        goto Cleanup;
    }
    new_file_written = fwrite(output_buffer + old_file_size, 1, new_file_size, new_file);
    if (new_file_written != new_file_size)
    {
        fprintf(stderr, "File write failed (%zd vs %d bytes)\n",
                new_file_written, new_file_size);
        retval = 1;
        goto Cleanup;
    }
    fclose(new_file);
    new_file = NULL;

Cleanup:
    if (new_file != NULL)
    {
        fclose(new_file);
    }
    if (old_file != NULL)
    {
        fclose(old_file);
    }
    if (diff_file != NULL)
    {
        fclose(diff_file);
    }
    if (input_buffer != NULL)
    {
        free(input_buffer);
    }
    if (output_buffer != NULL)
    {
        free(output_buffer);
    }
    return retval;
}
