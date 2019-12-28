# NTRU Encryption 
# Author: Tsai Hao-Chang
# Date: 2019/12/23
# ref 
# - https://latticehacks.cr.yp.to/ntru.html
# - https://github.com/kpatsakis/NTRU_Sage/blob/master/ntru.sage
# - https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=4800404
import numpy as np
from random import randrange, randint
from binascii import hexlify, unhexlify
from polynomial_arithmetic import *
from libnum import *

# Define Class NTRU to Share Parameters
class NTRU:
    
    def __init__(self, securelevel):
        self.p = 3
        self.q = 2048
        if securelevel == 128:
            self.N = 439
            self.d = 9, 8, 5, 146, 112 # d1, d2, d3, dg, dm
        elif securelevel == 192:
            self.N = 593
            self.d = 10, 10, 8, 197, 158
        elif securelevel == 256:
            self.N = 743
            self.d = 11, 11, 15, 247, 204 # d1, d2, d3, dg, dm
        self.keygen()
    
    # Modular reduction (center lift)
    def balanced_mod(self, f, p):
        res = list(((f[i] + p//2) % p) - p//2 for i in range(f.size))
        return np.array(res)
  
    # Multiplication in X^N
    def convolution(self, f, g):
        fg = poly_mul(f, g)
        fg = np.append(np.zeros(self.N - fg.size % self.N, dtype=int), fg)
        res = np.zeros(self.N, dtype=int)
        for i in range(fg.size):
            res[i%self.N] += fg[i]
        return res

    # Random polynomial r for encryption
    def pn(self):
        d1,d2,d3,_,_ = self.d
        a = randint(2*d1, self.N - d2)
        p1 = random_poly(a, d1, d1)
        p2 = random_poly(self.N-a, d2, d2)
        p3 = random_poly(self.N, d3, d3)
        res = poly_add(self.convolution(p1, p2), p3)
        return res

    def ext_eculid(self, x, p):
        r = np.array([0])
        x_N = np.zeros(self.N + 1, dtype=int)
        x_N[0], x_N[-1] = 1, -1 

        f, g = x_N, x
        t1 = np.array([0])
        t2 = np.array([1])
        
        while True:
            q, r = poly_div_gfp(f, g, p)
            t = poly_minus(t1, self.convolution(t2, q))
            t = t % p
            #print (q,f,g,r,t1,t2,t)
            f, g = g, r
            t1, t2 = t2, t
            if r.size == 1 and r[0] == 0:
                raise Exception('modular inverse does not exist')
            elif r.size == 1 and r[0] != 0:
                inv = (modinv(r[0], p) * t2) % p
                return inv
            
    def invertmodpower2(self , f, q):
        #assert q.is_power_of(2) # sage
        g = self.ext_eculid(f,2)
        #print ("g: ",g)
        while True:
            r = self.balanced_mod(self.convolution(g, f), q)
            # remove pre-0
            r = zero_remove(r)
            if r.size == 1 and r[0] == 1:
                return g
            g = self.balanced_mod(self.convolution(g, poly_minus(np.array([2]), r)), q)
            
    def keygen(self):
        print ("[+] Generating NTRU key...")
        d1,d2,d3,dg,dm = self.d
        while True:
            try:
                f = self.pn()
                f = poly_add(np.array([1]), 2*f)
                f = zero_remove(f)
                f3 = self.ext_eculid(f, 3)
                fq = self.invertmodpower2(f, self.q)
                break
            except:
                pass
        
        g = random_poly(self.N, dg, dg-1)
        self.pub = self.balanced_mod(3 * self.convolution(fq, g), self.q)
        self.priv = f, f3

    def encrypt(self, msg):
        r = random_poly(self.N, self.d[3], self.d[3]-1)
        return self.balanced_mod(poly_add(self.convolution(self.pub, r), msg), self.q)

    def decrypt(self, cipher):
        f,f3 = self.priv
        a = self.balanced_mod(self.convolution(cipher, f), self.q)
        return self.balanced_mod(self.convolution(a, f3), 3)

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
        for i in range(10 + padlen):
            msg = np.delete(msg, -1)
        return msg
    else:
        for i in range(10):
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
        d = ntrucipher.decrypt(c)
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