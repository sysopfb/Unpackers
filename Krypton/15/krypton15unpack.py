#Krypton 15 unpacker
#By Jason Reaves and Jonathan McCay

import struct
import sys
import base64
import os
from ctypes import *

nt = windll.ntdll

def LZNT_decompress(buffer, pos):
    size = len(buffer)
    uncompressed_buffer = create_string_buffer(2*size)
    final_size = c_ulong(0)
    nt.RtlDecompressBuffer(
        258,
        uncompressed_buffer,
        2*size,
        c_char_p(buffer[pos:]),
        size,
        byref(final_size)
        )
    return uncompressed_buffer

exe = open(sys.argv[1],'rb').read()
exe = exe[1024:]

start = exe.index('\x00\x00\x40\x00'+'\x00'*8)-5

(unk,xorkey2,unk,unk,unk,unk,unk,xorkey1,) = struct.unpack_from('<IBIIIIIB', exe[start:])

blob = bytearray(exe[start+39:])
for i in range(len(blob)):
	blob[i] ^= xorkey1

dec1 = base64.b64decode(blob)
dec1 = bytearray(dec1)
for i in range(len(dec1)):
	dec1[i] ^= xorkey2

decompressed = LZNT_decompress(str(dec1),0)
open(sys.argv[1]+'.unpacked','wb').write(decompressed)
