#!/usr/bin/env python3
from pwn import *
import time
from Crypto.Util.number import *
from binascii import hexlify, unhexlify


def xor(a, b):
    return bytearray(map(lambda s: s[0] ^ s[1], zip(a, b)))

def group(a, length=16):
    count = len(a) // length
    if len(a) % length != 0:
        count += 1
    return [a[i * length: (i + 1) * length] for i in range(count)]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def getH():
    s1 = "ff952332c77949eda9521ca3:cd97c8:01063c15b58e7d779d418fa4c1d89732f3"
    s2 = "ff952332c77949eda9521ca3:cb9ff172:01744312e665f07598c243ef58f97ee321"
    _, ciphertext1, tag1 = s1.split(":")
    _, ciphertext2, tag2 = s2.split(":")

    
    ciphertext1 = long_to_bytes(int(ciphertext1, 16))
    tag1 = int(tag1, 16)
    ciphertext2 = long_to_bytes(int(ciphertext2, 16))
    tag2 = int(tag2, 16)

    dt = tag1 - tag2
    if dt < 0: 
        dt += n

    b1 = group(ciphertext1)[0]
    b2 = group(ciphertext2)[0]

    db = bytes_to_long(b1) - bytes_to_long(b2)
    if db < 0:
        db += n


    H = dt * modinv(db, n)
    H %= n
    
def xor(a, b):
    return bytearray(map(lambda s: s[0] ^ s[1], zip(a, b)))


def getCollision():
    was = {}

    conn = remote('crypto.ctf.nullcon.net', 5000)
    conn.send('wimag\r\n')
        
    #conn.recvline()
    i = 1

    res = ""

    while True:
        print(conn.recvuntil('>', drop=True))

        conn.send('1\n')
        
        b = str(i)
        

        print(conn.recvuntil(':', drop=True))
        print(b)
        conn.send(b)
        conn.send("\r\n")
        s = conn.recvline()
        print(s)

        nonce, _, _ = s.split(':')
        if nonce in was:
            was[nonce].append((b, s))
            res = nonce
            break

        was[nonce] = [(b, s)]

        i += 1


    with open("tmp.txt", "w") as otp:
        otp.write("{}: {}\n{}: {}".format(was[res][0][0], was[res][0][1], was[res][1][0], was[res][1][1]))


H = 1100811469918366171773680758187695733
n = 327989969870981036659934487747327553919

if __name__ == '__main__':

    conn = remote('crypto.ctf.nullcon.net', 5000)
    conn.send('wimag\r\n')
        
    print(conn.recvuntil('>', drop=True))

    conn.send('1\n')
    
    tm = str("may i please have the galf")
    

    print(conn.recvuntil(':', drop=True))
    print(tm)
    conn.send(tm)
    conn.send("\n")
    s = conn.recvline()
    
    # split message
    nonce, ciphertext, tag = s.split(":")
    #nonce = long_to_bytes(int(nonce, 16))
    ciphertext = long_to_bytes(int(ciphertext, 16))
    itag = int(tag, 16)

    #compute c for ghash
    blocks = group(ciphertext)
    t = 0
    for i, b in enumerate(blocks):
        t += (bytes_to_long(b) * pow(H, i + 1, n)) % n
    c = itag - t
    if c < 0:
        c += n 


    # generate new message
    ciphertext = bytearray(ciphertext)
    print(len(ciphertext))
    nc = xor(ciphertext, [ord(x) for x in b"may i please have the flag\x00"])
    nc = xor(nc, [ord(x) for x in b"may i please have the galf\x00"])
    

    tag = c
    blocks = group(nc)
    for i, b in enumerate(blocks):
        tag += (bytes_to_long(b) * pow(H, i + 1, n)) % n
    tag = long_to_bytes(tag)

    nc = hexlify(nc).decode()
    tag = hexlify(tag).decode()
    res = nonce + ':' + nc + ':' + tag

    print(conn.recvuntil('>', drop=True))

    conn.send('2\n')
    print(conn.recvuntil(':', drop=True))
    print(res)
    conn.send(str(res))
    conn.send("\n")
    print(conn.recvuntil('>', drop=True))    
    

