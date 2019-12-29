from ntru import NTRU
from binascii import hexlify, unhexlify
from libnum import *
from polynomial_arithmetic import random_poly
import numpy as np
# Encrypt a file
## Plaintext Mapping
## - Base3 encoding (1 0 -1)
def code_len(num):
    i = 0
    while True:
        a = num // (3**i)
        if a < 3:
            break
        i += 1
    return i + 1

def base3encode(msg):
    num = s2i(msg)
    enc = np.array([], dtype=int)
    i = code_len(num) - 1
    while i >= 0:
        a = num // (3 ** i)
        enc = np.append(enc, [a - 1])
        num %= (3 ** i)
        i -= 1
    return enc
    
def base3decode(msg):
    num = 0
    for i in msg:
        num = num * 3 + int(i + 1)
    dec = i2s(num)
    return dec

## int <=> bit stream(nparray)
## - int -> bin stream (in nparray) 
def int2bin(num, bl=8):
    bstr = bin(num)[2:]
    x = ' '.join(bstr).split(' ')
    res = [0]*(bl - len(x)) + x
    res = np.array(res, dtype=int)
    return res
    
## - bin stream (in nparray) -> int
def bin2int(ndarr):
    res = 0
    for i in range(ndarr.size):
        res *= 2
        res += ndarr[i]
    return res

## Padding the base3-encoded message
## with last 10 element record length of padding
def padding(msg, bs):
    if (msg.size + 10) % bs != 0:
        padlen = bs - (msg.size + 10) % bs
        msg = np.append(msg, random_poly(padlen, padlen//4, padlen//4))# np.zeros(bs - msg.size % bs, dtype=int))
        msg = np.append(msg, int2bin(padlen, 10))
        return msg
    else:
        msg = np.append(msg, [0]*10)
        return msg

def unpadding(msg, bs):
    padlen = bin2int(msg[-10:])
    if padlen != 0:
        for _ in range(10 + padlen):
            msg = np.delete(msg, -1)
        return msg
    else:
        for _ in range(10):
            msg = np.delete(msg, -1)
        return msg
    
## bit stream (in ndarray) <=> bytes
## - bit stream (in ndarray) -> bytes
def bin2byte(ndarr):
    if ndarr.size % 8 != 0:
        ndarr = np.append(ndarr, np.zeros(8 - ndarr.size % 8, dtype=int))
    res = b''
    for i in range(0,ndarr.size,8):
        tmp = ndarr[i:i+8]
        s = 0
        for j in range(8):
            s *= 2
            s += tmp[j]
        res += i2s(s)
    return res
    
## - bytes -> bit stream (in ndarray)
def byte2bin(b):
    ndarr = np.array([], dtype=int)
    for c in b:
        tmp = int2bin(c)
        ndarr = np.append(ndarr, tmp)
    return ndarr

## Implement the file Encrytion & Decryption
def encrypt_fn(fn, cipher):
    print (f'[+] Opening file {fn}...')
    f = open(fn, 'rb')
    message = f.read()
    f.close()
    print (f'[+] Encrypting file {fn}...')
    ntrucipher = cipher
    # Base3 encoding
    bs = ntrucipher.N
    message = base3encode(message)
    message = padding(message, bs)
    
    #m = randommessage(ntrucipher.N)
    cipherbinary = np.array([], dtype=int)
    for i in range(0, len(message), bs):
        #m = bytes2poly(message[i:i+bs])
        m = message[i:i+bs] # Base3 encoded array
        c = ntrucipher.encrypt(m)
        if c.size < bs:
            c = np.append([0]*(bs-c.size), c)
        for j in c:
            # integer -> 11 bits array
            cipherbinary = np.append(cipherbinary, int2bin(j % ntrucipher.q, 11))
        #d = ntrucipher.decrypt(c)
        #print (list(m) == list(d))
    
    ciphertext = bin2byte(cipherbinary)
    f = open(fn + '.enc', 'wb')
    f.write(ciphertext)
    f.close()
    print (f'[+] Encryped file saved to {fn}.enc')

def decrypt_fn(fn, cipher):
    print (f'[+] Opening file {fn}...')
    f = open(fn, 'rb')
    ciphertext = f.read()
    f.close()
    print (f'[+] Decrypting file {fn}...')
    ntrucipher = cipher
    bs = ntrucipher.N
    
    cipherbinary = byte2bin(ciphertext)
    # each 11 bits -> coeff
    cipherpoly = np.array([], dtype=int)
    for i in range(0, cipherbinary.size, 11):
        tmp = cipherbinary[i:i+11]
        tmp = bin2int(tmp)
        cipherpoly = np.append(cipherpoly, [tmp])

    plain = np.array([], dtype=int)
    for i in range(0, cipherpoly.size-1, bs):
        c = cipherpoly[i:i+bs]
        d = ntrucipher.decrypt(c)
        plain = np.append(plain, d)
        
    plain = unpadding(plain, bs)
    plaintext = base3decode(plain)
    #print (plaintext)
    
    f = open(fn + '.dec', 'wb')
    f.write(plaintext)
    f.close()
    print (f'[+] Decryped file saved to {fn}.dec')
    
cipher = NTRU(256)
encrypt_fn('plain.txt', cipher)
decrypt_fn('plain.txt.enc', cipher)
a = input("Press any key to close...")