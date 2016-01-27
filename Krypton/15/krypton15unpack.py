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
#Can do 612 here and take out the if else chain and while loop below which works most of the time
exe = exe[512:]

while exe != []:
	start = exe.index('\x00\x00\x40\x00'+'\x00'*8)-5

	(unk,xorkey2,unk,unk,unk,unk,unk,xorkey1,) = struct.unpack_from('<IBIIIIIB', exe[start:])
	if xorkey2 != 0 and xorkey1 != 0:
		break
	elif len(exe) > 100:
		exe = exe[100:]
	else:
		print("Couldn't find the payload")
		sys.exit(-1)
blob = bytearray(exe[start+39:])
for i in range(len(blob)):
	blob[i] ^= xorkey1

dec1 = base64.b64decode(blob)
dec1 = bytearray(dec1)
for i in range(len(dec1)):
	dec1[i] ^= xorkey2

decompressed = LZNT_decompress(str(dec1),0)
open(sys.argv[1]+'.unpacked','wb').write(decompressed)
