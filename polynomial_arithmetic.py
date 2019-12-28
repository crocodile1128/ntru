# Define the array-type polynomial
# Author: Tsai Hao-Chang
# Date: 2019/12/29
import numpy as np

def random_poly(n, o, mo):
    s = [1]*o + [-1]*mo + [0]*(n - o - mo)
    s = np.array(s)
    np.random.shuffle(s)
    return s

# Poly remove pre 0
def zero_remove(x):
    while x.size > 0 and x[0] == 0:
        x = np.delete(x, 0)
    return x

# Addition
def poly_add(x, y):
    if x.size == y.size:
        res = x + y
    else:
        if x.size > y.size:
            y = np.append(np.zeros(x.size - y.size, dtype=int), y)
            res = x + y
        else:
            x = np.append(np.zeros(y.size - x.size, dtype=int), x)
            res = x + y
    while res.size != 0 and res[0] == 0:
        res = np.delete(res, 0)
    return res

# Subtraction
def poly_minus(x, y):
    if x.size == y.size:
        res = x - y
    else:
        if x.size > y.size:
            y = np.append(np.zeros(x.size - y.size, dtype=int), y)
            res = x - y
        else:
            x = np.append(np.zeros(y.size - x.size, dtype=int), x)
            res = x - y
    while res.size != 0 and res[0] == 0:
        res = np.delete(res, 0)
    return res

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    if m == 2:
        return 1
    if a < 0:
        a = a + m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
# Polynomial Multiplication
def poly_mul(x, y):
    length = x.size + y.size - 1
    res = np.zeros(length, dtype=int)
    for i in range(len(x)):
        # shift
        tmp = np.append(np.zeros(x.size-i-1, dtype=int), y)
        tmp = np.append(tmp, np.zeros(i, dtype=int))
        # scalar multiple
        tmp = x[x.size-i-1] * tmp
        # addition
        res = (res + tmp)
    return res
    
def poly_div_gfp(x, y, p):
    x = zero_remove(x)
    y = zero_remove(y)

    if x.size >= y.size:
        ql = x.size - y.size + 1
        q = np.zeros(ql, dtype=int)
        u = modinv(y[0], p)
        for i in range(ql):
            if x.size >= y.size and x[0] != 0:
                q[i] = (x[0] * u) % p
            else:
                q[i] = 0
            v = (q[i] * np.append(y, np.zeros(ql-i-1, dtype=int))) % p
            #print (v)
            x = x - v
            x = np.delete(x, 0)
        x = zero_remove(x)
        r = x % p
    else:
        q = np.array([0])
        r = x
    if r.size == 0:
        r = np.array([0])
    return q, r