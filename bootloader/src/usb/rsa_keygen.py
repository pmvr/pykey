from sympy.ntheory import isprime
from sympy import mod_inverse
import os

def gen_prime(byte_length):
    while True:
        p = int.from_bytes(os.urandom(byte_length), 'big') | 1
        if p.bit_length() != byte_length*8:
            continue
        if isprime(p):
            return p
        p += 2
        

while True:
    p = gen_prime(128)
    q = gen_prime(128)
    m = p*q
    if m.bit_length() < 2048:
        continue
    
    e = 3
    try:
        d = mod_inverse(e, (p-1)*(q-1))
    except ValueError:
        continue
    
    break

print("modulus = %0512x" % m);
print("sk = %0512x" % d);
print()

modulus =  "%0512x" % m
for i in range(0, len(modulus), 2):
    print("0x%s, " % modulus[i:i+2], end='')
print()
