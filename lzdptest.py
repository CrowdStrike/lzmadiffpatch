#! /usr/bin/env python
#
# This is a simple test harness for lzmadiff/lzmapatch
#
# Copyright 2021 CrowdStrike, Inc.
#
# This file may be used, modified, and distributed under the terms
# found in the file LICENSE in the same directory.

from __future__ import unicode_literals
from __future__ import division

import argparse
import unittest
import tempfile
import os
import shutil
import struct
import subprocess
import sys

LZMADIFF_PROG = 'lzmadiff'
LZMAPATCH_PROG = 'lzmapatch'

def do_diff_test(test_name, old_file_bytes, new_file_bytes):
    temp_dir = tempfile.mkdtemp()
    try:
        with open(os.path.join(temp_dir, 'oldfile.bin'), 'wb') as outf:
            outf.write(old_file_bytes)
        with open(os.path.join(temp_dir, 'newfile.bin'), 'wb') as outf:
            outf.write(new_file_bytes)
        try:
            subprocess.check_output(
                [LZMADIFF_PROG, "oldfile.bin", "newfile.bin", "diff.lzdiff"],
                cwd=temp_dir)
        except subprocess.CalledProcessError as cpe_exc:
            e = AssertionError(
                "%s: lzmadiff returned code %d" %
                (test_name, cpe_exc.returncode))
            e.__cause__ = None
            raise e
        try:
            subprocess.check_output(
                [LZMAPATCH_PROG, "diff.lzdiff", "oldfile.bin", "newfile2.bin"],
                cwd=temp_dir)
        except subprocess.CalledProcessError as cpe_exc:
            e = AssertionError(
                "%s: lzmapatch returned code %d" %
                (test_name, cpe_exc.returncode))
            e.__cause__ = None
            raise e

        with open(os.path.join(temp_dir, "newfile2.bin"), 'rb') as inf:
            returned_data = inf.read()
        assert returned_data == new_file_bytes, \
            "%s: reconstructed data not equal to old data" % (test_name,)
    finally:
        shutil.rmtree(temp_dir)

class LzdiffTest(unittest.TestCase):
    def test_single_bytes(self):
        for old_byte in range(1, 256, 7):
            for new_byte in range(0, 256, 11):
                do_diff_test("single byte %d %d" % (old_byte, new_byte),
                             b'%c' % old_byte, b'%c' % new_byte)

    def test_linear_file(self):
        base = b''.join(b'%c' % x for x in range(256))
        old_file_bytes = base * 9
        for szdiff in range(5, 500, 7):
            new_file_bytes = old_file_bytes[:-szdiff] + old_file_bytes[0:szdiff]
            do_diff_test("Linear %d" % szdiff,
                         old_file_bytes[:-szdiff], new_file_bytes)

    def test_aaa_bbb_aaa(self):
        for major_byte in range(3, 255, 13):
            old_file_bytes = (b'%c' % major_byte
                              + b'%c' % (256 - major_byte)) * 50000
            for minor_byte in range(4, 255, 11):
                new_file_bytes = (
                    old_file_bytes[0:50000]
                    + b'%c' % minor_byte * 500
                    + old_file_bytes[50500:])
                do_diff_test("aba %d %d" % (major_byte, minor_byte),
                             old_file_bytes, new_file_bytes)

    def test_aaa_bbbxyzbbb_aaa(self):
        for major_byte in range(3, 255, 13):
            old_file_bytes = (b'%c' % major_byte
                              + b'%c' % (256 - major_byte)) * 50000
            for minor_byte in range(4, 255, 11):
                new_file_bytes = (
                    old_file_bytes[0:50000]
                    + b'%c' % minor_byte * 100
                    + b''.join(b'%c' % x for x in range(256))
                    + b'%c' % minor_byte * 100
                    + old_file_bytes[50500:])
                do_diff_test("abzba %d %d" % (major_byte, minor_byte),
                             old_file_bytes, new_file_bytes)

    def test_binaryesque(self):
        old_file_bytes = b'\xAA\xAA\xAA\xAA\x00\x01\x55'*60 + b'\x99\xCC\x22'
        new_file_bytes = b'\xAA\xAA\xAA\xAA\x00\x01\x52'*60 + b'\x99\xCC\x22'
        for last_byte in range(4, 255, 11):
            do_diff_test("binaryesque %d" % (last_byte,),
                         old_file_bytes + b'%c' % last_byte,
                         new_file_bytes + b'%c' % last_byte)

    def test_long_english(self):
        text1 = """
This is a whole long bunch of English because of the peculiar properties of
English text. Specifically, I'm looking for data I can generate easily that
has an entropy of between two and six bits per byte. Therefore, I'm just going
to keep typing until I've filled up approximately nine or ten lines of
nonsense. Since this test is written in python, I suppose that it'd be
traditional to include here some sort of reference to Monty Python's works,
but even Guido has said that he's tired of all the Monty Python in-jokes
people scatter all through python documentation, so I'll just mention
something about spam and leave it at that.
""".strip().replace('\n', ' ').encode('utf-8')
        for last_byte in range(4, 255, 11):
            do_diff_test("long English %d" % (last_byte,),
                         text1 + b'%c' % last_byte,
                         text1.replace(b'u', b'U') + b'%c' % last_byte)

    def test_exponential_seq(self):
        old_bytes = b''.join(struct.pack('<H', pow(5, x+256, 1 << 17) >> 1)
                             for x in range(4000))
        new_bytes = b''.join(struct.pack('<H', pow(7, x+256, 1 << 17) >> 1)
                             for x in range(4000))
        for start in range(0, 500, 97):
            for end in range(len(new_bytes) - 500, len(new_bytes), 109):
                do_diff_test("exponential %d %d" % (start, end),
                             old_bytes[start:end], new_bytes[start:end])

    def test_exponential_aaa_bbb_aaa(self):
        old_bytes = b''.join(struct.pack('<H', pow(5, x+256, 1 << 17) >> 1)
                             for x in range(4000))
        filler = b''.join(struct.pack('<H', pow(7, x+256, 1 << 17) >> 1)
                             for x in range(4000))
        for start in range(2, 7500, 597):
            for filler_len in range(5, len(filler), len(filler) // 9):
                do_diff_test("exponential_aba %d %d" % (start, filler_len),
                             old_bytes,
                             old_bytes[start:]
                             + filler[:filler_len]
                             + old_bytes[:start])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Test lzmadiff/lzmapatch combination')
    parser.add_argument(
        '--diff',
        dest='diff',
        help='lzmadiff path name',
        required=True)
    parser.add_argument(
        '--patch',
        dest='patch',
        help='lzmapatch path name',
        required=True)
    (args, rest) = parser.parse_known_args()
    LZMADIFF_PROG = os.path.abspath(args.diff)
    LZMAPATCH_PROG = os.path.abspath(args.patch)
    unittest.main(argv=[sys.argv[0]] + rest)
