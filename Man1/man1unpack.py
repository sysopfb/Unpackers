#Man1 crypter unpacker proof of concept
#Vawtrak sample - 4260b59d2d6023f3be6cbe4c388d7cfe
#by Jason Reaves


import struct
import sys
import os
from ctypes import *
import binascii
from argparse import ArgumentParser
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine

from pdb import pm

#On linux I use a shared object from lznt1 written in C
lznt = cdll.LoadLibrary('./libMSCompression.so')

def LZNT_decompress(buffer, pos):
	data = create_string_buffer(buffer)
	uncompressed_data = create_string_buffer(len(data)*2)
	ret = lznt.lznt1_decompress(byref(data), len(data), byref(uncompressed_data), len(data)*2)
	return uncompressed_data.raw

"""
#Running from windows
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
"""


data = open(sys.argv[1],'rb').read()

def DecodeHdrVal(val):
	result = 0
	v2 = val
	if((val & 0xFFFF) > 32000):
		v2 = val - 32000
	v4 = (v2 & 0xFFFF) % 100
	v3 = (v2 & 0xFFFF) % 100
	if(v4 > 50):
		v3 = v3 >> 1
	result = (((v2 - v4 - (val >> 16) / v3) & 0xFFFF) / v3)
	result += (((v2 - v4 - (val >> 16) / v3) & 0xFFFF) % v3) << 16
	#print(hex(result))
	return result

def GetDataLength(data):
	return DecodeHdrVal(struct.unpack_from('<I', data[4:])[0]) - 0x1c

#data should be bytearray - used for shellcode
def sub_0650(data, length, key):
	result = length
	temp = 0
	temp2 = 0
	for i in range(length):
		data[i] ^= (i * temp * key) & 0xFF
		if(i<key):
			result = (key - temp) & 0xFFFFFFFF
			temp2 = key - temp
		else:
			temp2 = key + temp * key * (i + 1)
		temp = key * temp2
	print(binascii.hexlify(str(data)))
	return result
		

def find_first(data, setNum):
	i = 0
	#for i in range(0, len(data)):
	while i < len(data)-1:
		increment = 1
		(CheckVal1,) = struct.unpack_from('<H',data[i:])
		if CheckVal1 > 1500 and CheckVal1 < 4000:	#pony	338496ffced59059ddb0deb4600d0599
		#if CheckVal1 > 1500 and CheckVal1 < 3500:
			#print(hex(CheckVal1))
			(CheckVal2,) = struct.unpack_from('<H',data[i+2:])
			#Added CheckVal1+ for same pony
			if CheckVal2 >= CheckVal1 + 700 and CheckVal2 <= CheckVal1+CheckVal1 + 1967:
			#if CheckVal2 >= CheckVal1 + 700 and CheckVal2 <= CheckVal1 + 1967:
				(offset,) = struct.unpack_from('<H',data[i+4:])
				if(i + offset + 6 < len(data) and struct.unpack_from('<H', data[i+offset+6:])[0] == offset + CheckVal1 + 2 * CheckVal2):
					increment = offset+8
					if(DecodeHdrVal(struct.unpack_from('<I', data[i+6:])[0]) == setNum):
						return i+6
		i += increment
	return 0
def main_loop(setnum, index, data, checkflag):
	while True:		
		test = find_first(data, setnum)
		if test == 0:
			print("DONE")
			return 0
		curr = data[test:]
		(param1,) = struct.unpack_from('<I', curr[8:])
		test2 = DecodeHdrVal(param1)
		if test2 == index:
			break
		test3 = DecodeHdrVal(struct.unpack_from('<I', curr[4:])[0])
		data = data[test+test3:]

	temp = curr[8:]
	test = DecodeHdrVal(struct.unpack_from('<I', temp[4:])[0])

	test = GetDataLength(curr)
	#Allocates test+0x1000 memory

	#Data to copy
	#Stores curr+0x1c for me was 45F022
	#Header is 0x1c in length?

	temp2 = curr[0x1c:]
	blob = temp2[:test]

	#16 bytes into header
	key = DecodeHdrVal(struct.unpack_from('<I', temp[8:])[0])
	print(hex(key))
	blob = bytearray(blob)
	if checkflag:
		ret = sub_0650(blob, test, key)

	#Length without -1c
	uncompressedSize = DecodeHdrVal(struct.unpack_from('<I', temp[16:])[0])
	print(hex(uncompressedSize))
	#alloc mem 0x1000+uncompressedSize

	#Jump table depending on this value 0 = copy data, 1 = decompress, 2 = decompress
	unk2 = DecodeHdrVal(struct.unpack_from('<I', temp[12:])[0])
	print(hex(unk2))
	return (key, uncompressedSize, blob, unk2)


#Shellcode
i = 1
t = 1
shellcode = ""

while t != 0: 
	t = main_loop(6, i, data, True)
	if t != 0:
		shellcode += binascii.hexlify(str(t[2]))
	i += 1



#After building this shellcode an address found using find_first(data,5) with an index of 1 is used
"""
i = 1
t = 1
ret = ""

while t != 0: 
	t = main_loop(5, i, data, True)
	if t != 0:
		scode(t[2], t[1], t[0])
		ret += binascii.hexlify(str(t[2]))
	i += 1
print(ret)
"""
#Zeroes out bytes 1-5 from DEADBEEF
#Big shellcode called with 4 params
#beginning of exe in memory
#0
#0x182208
#0xA


def scode(data, length, key, shellcode):
	def code_sentinelle(jitter):
		jitter.run = False
		jitter.pc = 0
		return True


	myjit = Machine("x86_32").jitter("tcc")
	myjit.init_stack()

	run_addr = 0x40000000
	myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, shellcode)

	#myjit.jit.log_regs = True
	#myjit.jit.log_mn = True
	#myjit.jit.log_newbloc = True

	myjit.add_breakpoint(0x1337beef, code_sentinelle)
	myjit.vm.add_memory_page(0x10000000, PAGE_READ | PAGE_WRITE, data)
	#myjit.add_breakpoint(0x40000000, code_sentinelle)
	myjit.push_uint32_t(key)
	myjit.push_uint32_t(len(data))
	myjit.push_uint32_t(0x10000000)
	myjit.push_uint32_t(0x1337beef)
	myjit.init_run(run_addr)
	myjit.continue_run()
	return myjit.cpu.get_mem(0x10000000,len(data))



print(shellcode)
###Allocates prevAddr+8int size buffer

#Finds set 0 index 1
i = 1
t = 1
ret = ""
while t != 0:
	t = main_loop(0, i, data, False)
	if t != 0:
		temp = scode(str(t[2]), len(t[2]), t[0], binascii.unhexlify(shellcode))
		if t[3] == 1 or t[3] == 2:
			temp = LZNT_decompress(temp, 0)
		ret += str(temp[:t[1]])
		if t[1] > len(temp):
			ret += '\x00' * (t[1] - len(temp))
			
	i += 1

open(sys.argv[1]+'_unpacked.bin','wb').write(ret)
