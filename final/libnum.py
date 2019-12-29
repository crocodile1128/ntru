# Convert bytes/str <=> int
# Author: Tsai Hao-Chang
# Date: 2019/12/29
from binascii import hexlify, unhexlify
def s2i(s):
	if isinstance(s,bytes):
		res = hexlify(s)
	elif isinstance(s,str):
		res = hexlify(s.encode('utf-8'))
	return int(res, 16)

def i2s(n):
	res = hex(n)[2:] # hex = '0x....'
	if len(res) % 2 != 0:
		res = '0' + res
	res = unhexlify(res)
	return res