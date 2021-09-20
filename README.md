# LzmaDiffPatch

This is a matched pair of command line utilities - `lzmadiff` and
`lzmapatch` - that produce and apply binary "diffs" based on the
LZMA2 compression algorithm (the same compression algorithm used in the
tool `xz`). That is, given two input files (designated "old" and
"new"), the program `lzmadiff` can create a file of instructions for
`lzmapatch` that tells `lzmapatch` how to turn the "old" file into the
"new" file. Generally, if the "old" and "new" files are rather
similar, the file of instructions will be much smaller than either
input file.

Although it's possible to use these utilities as-is, the real purpose
of these utilities is as a demonstration of how to create and apply
such binary diff files using the public domain [LZMA
SDK](https://www.7-zip.org/sdk.html) and MIT-Licensed [`minlzma`
library](https://github.com/ionescu007/minlzma).

**Any actual product based on this code should include features
wrapping the raw binary diff with some file integrity checks**. For
example, one might use this code to create a differential file format
which includes the sha256 checksums of both the "old" and the "new"
file.

## Building

This project builds with [`cmake`](https://cmake.org/). Note that the
build process will download and patch the LZMA SDK source, and will
also create a git clone of the `minlzma` project.

On Windows with Visual Studio 2019, you should be able to use
File->Open->CMake and point it at the top-level `CMakeFiles.txt` and
go from there.

If you prefer the Windows command line, you can do:

    cd lzmadiffpatch
    cmake .
    cmake --build . --config Debug
    ctest .

On Mac or Linux, (or WSL) the recommended way to build with `cmake` is:

    cd lzmadiffpatch
    mkdir Debug
    cd Debug
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    cmake --build .
    ctest .

Replace `Debug` with `Release` in the above commands to build without
debugging information, or see [cmake.org](https://cmake.org/) for more
information about available build types.

## Use

Both commands take no options, just three file names: two files to
read from, and a file to write to.

    lzmadiff old_file new_file diff_file

Reads from `old_file` and `new_file`, writes to `diff_file`.

    lzmapatch diff_file old_file new_file

Reads from `diff_file` and `old_file`, writes to `new_file`.

## Limitations

The diffing algorithm fundamentally won't work if the "old" file is
larger than the maximum history size for LZMA2 (4 GiB - 1), and
generally performs much better on files smaller than 1 GiB. Therefore
the `lzmadiff` utility limits its history size to 3GB and rejects
files larger than that, and also rejects file pairs where the total
exceeds 3 GiB. The intended use is for input file sizes ranging from a
few KiB to a few MiB. (Though it will continue to work into the
hundreds of MiB range, some tests show effectiveness drops drastically
as file size increases above about 15 MiB)

During `lzmapatch`, the full contents of both the "old" and "new" file
will be held in memory temporarily. Therefore, memory-constrained
systems may place their own limitations on how large the "old" and
"new" files can be.

## Licensing and Copyright

The file `patch.py` is Copyright (c) 2008-2016 anatoly techtonik and
is available under the MIT License in his github repository
[python-patch](https://github.com/techtonik/python-patch).

The file `lzma1900.diff`, which represents a series of changes to the
[LZMA SDK](https://www.7-zip.org/sdk.html), is placed in the public
domain.

The remainder of this repository (the `lzmadiff` and `lzmapatch`
programs, tests, and build files) is offerred under the terms in the
file `LICENSE`. (Standard MIT license terms)

Note that when built the `lzmapatch` binary will include code from the
[`minlzma` library](https://github.com/ionescu007/minlzma) which is
copyright (c) 2020 Alex Ionescu.
