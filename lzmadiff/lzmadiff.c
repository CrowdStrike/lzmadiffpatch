/*!

   @file lzmadiff/lzmadiff.c

   @brief Command-line executable to create LZMA2 streams that represent
          the difference between two files.

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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Files included from lzma1900/C */

#include "7zTypes.h"
#include "7zFile.h"
#include "7zCrc.h"
#include "Lzma2Enc.h"
#include "Sha256.h"

#define MAX_ALLOWED_FILE_SIZE (3ULL << 30)

/*
 * This is a "class" in the style of the LZMA SDK's C code. Essentially, it's
 * doing a class manually.
 *
 * This particular class implements the ISeqInStream interface to present an
 * ISeqInStream that represents the concatenation of two other ISeqInStreams.
 */
typedef struct _JoinedInStreamThing
{
    /* The "virtual table" pointing to this object's methods */
    ISeqInStream vt;

    /* In a real OO language, these next would be the instance member variables */

    ISeqInStream *src0;    /* First source */
    ISeqInStream *src1;    /* Second source */
    int current_src;       /* A 0 or 1 to indicate which source we're reading from */
} JoinedInStreamThing;

/* Implementation of ISeqInStream's Read method for JoinedInStreamThing */
static SRes JoinedInStreamThing_Read(
    const ISeqInStream *p, void *buf, size_t *size)
{
    SRes retval;
    size_t old_size;

    JoinedInStreamThing *self = CONTAINER_FROM_VTBL(p, JoinedInStreamThing, vt);

    if (! (self->current_src))
    {
        old_size = *size;

        retval = self->src0->Read(self->src0, buf, size);
        if (retval != SZ_OK)
        {
            return retval;
        }
        if ((old_size != 0) && (*size == 0))
        {
            /* we hit the end of src0 */
            self->current_src = 1;
            *size = old_size;
            /* Fall through to read src1 */
        }
        else
        {
            /* */
            return retval;
        }
    }
    return self->src1->Read(self->src1, buf, size);
}

/* Initializes a new JoinedInStreamThing instance */
static void JoinedInStreamThing_Init(
    JoinedInStreamThing *Joined,
    ISeqInStream *Source0,
    ISeqInStream *Source1)
{
    Joined->vt.Read = JoinedInStreamThing_Read;
    Joined->src0 = Source0;
    Joined->src1 = Source1;
    Joined->current_src = 0;
}

/* wrap the standard malloc and free calls as the LZMA SDK expects to see them */
static void *SzAlloc(ISzAllocPtr p, size_t size) {
    (void)(p);  /* deliberately not used parameter p */
    return malloc(size);
}

static void SzFree(ISzAllocPtr p, void *address) {
    (void)(p);  /* deliberately not used parameter p */
    free(address);
}

/* The LZMA SDK uses a structure of type ISzAlloc to communicate how to handle memory allocation */
static ISzAlloc myAlloc = {
    SzAlloc,
    SzFree
};

void PrintSha256(Byte *shastuff)
{
    int i;
    for (i=0; i < 32; i++)
    {
        printf("%02x", shastuff[i]);
    }
    printf("\n");
}

SRes File_GetSize(const char *filename, size_t *out)
{
    CSha256 sha256Scratch;
    Byte buff[1024];
    CFileSeqInStream inFile;
    SRes res;
    size_t portion;

    /* read the file through the sha256 thing, print for now for dbg */
    /* put file size in *out */
    FileSeqInStream_CreateVTable(&inFile);
    File_Construct(&inFile.file);

    Sha256_Init(&sha256Scratch);
    res = InFile_Open(&inFile.file, filename);
    if (res != SZ_OK)
    {
        fprintf(stderr, "Can not open file %s\n", filename);
        return res;
    }
    *out = 0;
    for (;;)
    {
        portion = 1024;
        res = inFile.vt.Read(&(inFile.vt), buff, &portion);
        if (res != SZ_OK)
        {
            fprintf(stderr, "Error reading file");
            return res;
        }
        *out += portion;
        if (portion == 0)
        {
            Sha256_Final(&sha256Scratch, buff);
            printf("%s: ", filename);
            PrintSha256(buff);
            return SZ_OK;
        }
        Sha256_Update(&sha256Scratch, buff, portion);
    }
}

int main(int argc, const char *argv[])
{
    CFileSeqInStream inFile1;
    CFileSeqInStream inFile2;
    CFileOutStream outStream;
    JoinedInStreamThing myJoint;

    CLzma2EncHandle lzma2thing = Lzma2Enc_Create(&myAlloc, &myAlloc);
    size_t file1_size;
    size_t file2_size;
    CLzma2EncProps lzma2props;
    SRes res;

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s oldfile newfile outputfile\n", argv[0]);
        return 2;
    }
    FileSeqInStream_CreateVTable(&inFile1);
    File_Construct(&inFile1.file);
    FileSeqInStream_CreateVTable(&inFile2);
    File_Construct(&inFile2.file);

    FileOutStream_CreateVTable(&outStream);
    File_Construct(&outStream.file);

    CrcGenerateTable();

    res = File_GetSize(argv[1], &file1_size);
    if (res != SZ_OK)
    {
        return res;
    }
    res = File_GetSize(argv[2], &file2_size);
    if (res != SZ_OK)
    {
        return res;
    }

    if ((file1_size >= MAX_ALLOWED_FILE_SIZE)
        || (file2_size >= MAX_ALLOWED_FILE_SIZE)
        || ((file1_size + file2_size) >= MAX_ALLOWED_FILE_SIZE))
    {
        fprintf(stderr, "Can't handle files that total larger than 3GB");
        return 1;
    }
    /* Now we know it's safe to cast file sizes to UInt32 */

    Lzma2EncProps_Init(&lzma2props);
    lzma2props.blockSize = file1_size + file2_size + 1;
    lzma2props.skipBytes = (UInt32)file1_size;      /* skipBytes is added by our patch to lzma1900 */
    Lzma2Enc_SetProps(lzma2thing, &lzma2props);
    Lzma2EncProps_Normalize(&lzma2props);

    if (InFile_Open(&inFile1.file, argv[1]) != 0)
    {
        fprintf(stderr, "Can not open file 1\n");
        return 1;
    }
    if (InFile_Open(&inFile2.file, argv[2]) != 0)
    {
        fprintf(stderr, "Can not open file 2\n");
        return 1;
    }
    if (OutFile_Open(&outStream.file, argv[3]) != 0)
    {
        fprintf(stderr, "Can not open output file\n");
        return 1;
    }
    JoinedInStreamThing_Init(
        &myJoint,
        &(inFile1.vt),
        &(inFile2.vt));

    if (Lzma2Enc_Encode2(lzma2thing,      /* CLzma2EncHandle p */
                         &(outStream.vt), /* ISeqOutStream *outStream */
                         NULL,            /* Byte *outBuf - unused with outStream*/
                         0,               /* size_t *outBufSize */
                         &(myJoint.vt),   /* ISeqInStream *inStream */
                         NULL,            /* const Byte *inData - unused */
                         0,               /* size_t inDataSize */
                         NULL) != SZ_OK)  /* ICompressProgress *progress - unused */
    {
        fprintf(stderr, "Failure in diff/compression\n");
        return 1;
    }
}
