# NTRU Encryption 
# Author: Tsai Hao-Chang
# Date: 2019/12/29
# ref 
# - https://latticehacks.cr.yp.to/ntru.html
# - https://github.com/kpatsakis/NTRU_Sage/blob/master/ntru.sage
# - https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=4800404
import numpy as np
from random import randrange, randint
from polynomial_arithmetic import *

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
        _,_,_,dg,_ = self.d
        while True:
            try:
                f = self.pn()
                f = poly_add(np.array([1]), 2*f)
                f = zero_remove(f)
                f3 = self.ext_eculid(f, self.p)
                fq = self.invertmodpower2(f, self.q)
                break
            except:
                pass
        
        g = random_poly(self.N, dg, dg-1)
        self.pub = self.balanced_mod(self.p * self.convolution(fq, g), self.q)
        self.priv = f, f3

    def encrypt(self, msg):
        r = random_poly(self.N, self.d[3], self.d[3]-1)
        return self.balanced_mod(poly_add(self.convolution(self.pub, r), msg), self.q)

    def decrypt(self, cipher):
        f,f3 = self.priv
        a = self.balanced_mod(self.convolution(cipher, f), self.q)
        return self.balanced_mod(self.convolution(a, f3), self.p)

