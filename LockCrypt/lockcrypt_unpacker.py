'''
This script unpacks a crypter being utilized by Locky and some other malware(chthonic and nymaim).
Named LockCrypt for now
1c80b1ba2c514bc1d32eb5b9909d79812ab8f2944548bc96757c1d992ce6d8ac
7a0f22b70e0410443834e4e3592940fdc56b0dff05020ca2d0ca3507b4aa2f3d

-Jason Reaves
24aug2017
'''
import sys
import re
import struct
import base64
import binascii
from z3 import *
import pefile



possible_decodes = [bytearray('\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00'), bytearray('\x4d\x5a\x80\x00\x01\x00\x00\x00\x04\x00\x10\x00')]

def solve_doublesub(input, output):
	hc_sub = BitVec('sub1', 32)
	delta_sub = BitVec('sub2', 32)

	s = Solver()

	second_delta = struct.unpack_from('<I', input)[0]
	s.add((BitVecVal(struct.unpack_from('<I',input)[0], 32) - hc_sub) - delta_sub == BitVecVal(struct.unpack_from('<I',output)[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[4:])[0], 32) - hc_sub) - second_delta == BitVecVal(struct.unpack_from('<I',output[4:])[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[8:])[0], 32) - hc_sub) - BitVecVal(struct.unpack_from('<I', input[4:])[0], 32) == BitVecVal(struct.unpack_from('<I',output[8:])[0], 32))
	return(s)

def solve_sub_hcxor(input, output):
	hc_xor = BitVec('xor1', 32)
	delta_sub = BitVec('sub1', 32)

	s = Solver()

	second_delta = struct.unpack_from('<I', input)[0]
	s.add((BitVecVal(struct.unpack_from('<I',input)[0], 32) ^ hc_xor) - delta_sub == BitVecVal(struct.unpack_from('<I',output)[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[4:])[0], 32) ^ hc_xor) - second_delta == BitVecVal(struct.unpack_from('<I',output[4:])[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[8:])[0], 32) ^ hc_xor) - BitVecVal(struct.unpack_from('<I', input[4:])[0], 32) == BitVecVal(struct.unpack_from('<I',output[8:])[0], 32))
	return(s)

def solve_xor_hcsub(input, output):
	hc_sub = BitVec('sub1', 32)
	delta_xor = BitVec('xor1', 32)

	s = Solver()

	second_delta = struct.unpack_from('<I', input)[0]
	s.add((BitVecVal(struct.unpack_from('<I',input)[0], 32) - hc_sub) ^ delta_xor == BitVecVal(struct.unpack_from('<I',output)[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[4:])[0], 32) - hc_sub) ^ second_delta == BitVecVal(struct.unpack_from('<I',output[4:])[0], 32))
	s.add((BitVecVal(struct.unpack_from('<I',input[8:])[0], 32) - hc_sub) ^ BitVecVal(struct.unpack_from('<I', input[4:])[0], 32) == BitVecVal(struct.unpack_from('<I',output[8:])[0], 32))
	return(s)

def get_rsrc(pe):
	ret = []
	for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
		if resource_type.name is not None:
			name = str(resource_type.name)
		else:
			name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
		if name == None:
			name = str(resource_type.struct.name)
		if hasattr(resource_type, 'directory'):
			for resource_id in resource_type.directory.entries:
				if hasattr(resource_id, 'directory'):
					for resource_lang in resource_id.directory.entries:
						data = pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
						ret.append((name,data,resource_lang.data.struct.Size,resource_type))
	return ret


def decoder(data):
	pe = pefile.PE(data=data)
	rsrcs = get_rsrc(pe)

	for rsrc in rsrcs:
		#Try z3 solvers
		a = bytearray(rsrc[1])
		for poss_decode in possible_decodes:
			s = solve_doublesub(a, poss_decode)
			if s.check() == sat:
				m = s.model()
				for d in m.decls():
					if d.name() == 'sub1':
						sub1 = m[d].as_long()
					elif d.name() == 'sub2':
						sub2 = m[d].as_long()
				print("Satisfied!")
				print("Sub1 Value: "+hex(sub1))
				print("Sub2 Value: "+hex(sub2))
				
				out = ""
				for i in range(0,len(a), 4):
					next_delta = struct.unpack_from('<I', a[i:])[0]
					temp = next_delta - sub1 - sub2
					temp &= 0xffffffff
					out += struct.pack('<I', temp)
					sub2 = next_delta
				return out
			else:
				print("Try xor version")
				s = solve_sub_hcxor(a, poss_decode)
				if s.check() == sat:
					m = s.model()
					for d in m.decls():
						if d.name() == 'sub1':
							sub1 = m[d].as_long()
						elif d.name() == 'xor1':
							xor1 = m[d].as_long()
					print("Satisfied!")
					print("Sub1 Value: "+hex(sub1))
					print("xor1 Value: "+hex(xor1))
					
					out = ""
					for i in range(0,len(a), 4):
						next_delta = struct.unpack_from('<I', a[i:])[0]
						temp = (next_delta ^ xor1) - sub1
						temp &= 0xffffffff
						out += struct.pack('<I', temp)
						sub1 = next_delta
					return out
				else:
					print("Try xor version 2")
					s = solve_xor_hcsub(a, poss_decode)
					if s.check() == sat:
						m = s.model()
						for d in m.decls():
							if d.name() == 'sub1':
								sub1 = m[d].as_long()
							elif d.name() == 'xor1':
								xor1 = m[d].as_long()
						print("Satisfied!")
						print("Sub1 Value: "+hex(sub1))
						print("xor1 Value: "+hex(xor1))
						
						out = ""
						for i in range(0,len(a), 4):
							next_delta = struct.unpack_from('<I', a[i:])[0]
							temp = (next_delta - sub1) ^ xor1
							temp &= 0xffffffff
							out += struct.pack('<I', temp)
							xor1 = next_delta
						return out

	return False

if __name__ == "__main__":
	data = open(sys.argv[1],'rb').read()
	t = decoder(data)
	if t:
		open(sys.argv[1]+'.unpacked', 'wb').write(t)
