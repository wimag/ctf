# Nullcon CTF

This directory contains solutions/writeups for _nullcon CTF 2019_ (02.02.2019)


## 2FUN

in this task we're given an encryption algorith resembling 2DES

```python
sbox = [210, 213, 115, 178, 122, 4, 94, 164, 199, 230, 237, 248, 54,
        217, 156, 202, 212, 177, 132, 36, 245, 31, 163, 49, 68, 107,
        91, 251, 134, 242, 59, 46, 37, 124, 185, 25, 41, 184, 221,
        63, 10, 42, 28, 104, 56, 155, 43, 250, 161, 22, 92, 81,
        201, 229, 183, 214, 208, 66, 128, 162, 172, 147, 1, 74, 15,
        151, 227, 247, 114, 47, 53, 203, 170, 228, 226, 239, 44, 119,
        123, 67, 11, 175, 240, 13, 52, 255, 143, 88, 219, 188, 99,
        82, 158, 14, 241, 78, 33, 108, 198, 85, 72, 192, 236, 129,
        131, 220, 96, 71, 98, 75, 127, 3, 120, 243, 109, 23, 48,
        97, 234, 187, 244, 12, 139, 18, 101, 126, 38, 216, 90, 125,
        106, 24, 235, 207, 186, 190, 84, 171, 113, 232, 2, 105, 200,
        70, 137, 152, 165, 19, 166, 154, 112, 142, 180, 167, 57, 153,
        174, 8, 146, 194, 26, 150, 206, 141, 39, 60, 102, 9, 65,
        176, 79, 61, 62, 110, 111, 30, 218, 197, 140, 168, 196, 83,
        223, 144, 55, 58, 157, 173, 133, 191, 145, 27, 103, 40, 246,
        169, 73, 179, 160, 253, 225, 51, 32, 224, 29, 34, 77, 117,
        100, 233, 181, 76, 21, 5, 149, 204, 182, 138, 211, 16, 231,
        0, 238, 254, 252, 6, 195, 89, 69, 136, 87, 209, 118, 222,
        20, 249, 64, 130, 35, 86, 116, 193, 7, 121, 135, 189, 215,
        50, 148, 159, 93, 80, 45, 17, 205, 95]
p = [3, 9, 0, 1, 8, 7, 15, 2, 5, 6, 13, 10, 4, 12, 11, 14]


def xor(a, b):
    return bytearray(map(lambda s: s[0] ^ s[1], zip(a, b)))


def fun(key, pt):
    assert len(pt) == BLOCK_LENGTH
    assert len(key) == KEY_LENGTH
    key = bytearray(unhexlify(md5(key).hexdigest()))
    ct = bytearray(pt)
    for _ in range(ROUND_COUNT):
        ct = xor(ct, key)
        for i in range(BLOCK_LENGTH):
            ct[i] = sbox[ct[i]]
        nct = bytearray(BLOCK_LENGTH)
        for i in range(BLOCK_LENGTH):
            nct[i] = ct[p[i]]
        ct = nct
    return hexlify(ct)


def toofun(key, pt):
    assert len(key) == 2 * KEY_LENGTH
    key1 = key[:KEY_LENGTH]
    key2 = key[KEY_LENGTH:]

    ct1 = unhexlify(fun(key1, pt))
    ct2 = fun(key2, ct1)

    return ct2

```

We are also given known ciphertext: `16 bit plaintext` -> `467a52afa8f15cfb8f0ea40365a6692`

The goal is to decrypt the flag `04b34e5af4a1f5260f6043b8b9abb4f8`


\\
After investigating `toofun` wee see that encryption process is basically excypting message with two 3-byte keys using `fun`. So step 1 woulbe be to learn how to decrypt message encrypted with `fun`. It can be done in quite straightforward way, just reversing all actions 1 by 1: 
```python



def defun(key, raw):
	rp = [0 for _ in range(len(p))]
	rsbox = [0 for _ in range(len(sbox))]

	for i in range(len(p)):
	    rp[p[i]] = i

	for i in range(len(sbox)):
	    rsbox[sbox[i]] = i


    ct = list(unhexlify(raw))
    key = bytearray(unhexlify(md5(key).hexdigest()))
    #print("\n\n")
    for _ in range(ROUND_COUNT):
        nct = bytearray(BLOCK_LENGTH)
        for i in range(BLOCK_LENGTH):
            nct[i] = ct[rp[i]]

        #print("DNCT: {}".format(str(nct)))
        
        for i in range(BLOCK_LENGTH):
            ct[i] = rsbox[nct[i]]
        
        ct = xor(ct, key)
    return hexlify(ct)
```


Now we have to find out 6-byte key, used for original encryption. Bruteforcing is not an option here. However, we know, that `fun(key[:3], plaintext) == defun(key[3:], ciphertext)` (by the definion of toofun). Knowing this we can make Meet-in-the-middle attack: encrypt known plaintext with all keys, while decrypting knwon ciphertext with the same keys, hoping to find a common result, thus ubtaining the full key. 

```python
fwd = {}
bwd = {}

k1 = ""
k2 = ""
for k in tqdm(keys):
    #print("{}".format(k))
    f = fun(k, b"16 bit plaintext")
    if f in bwd:
        print("FOUND: {} {}".format(k, bwd[f]))
        k1 = k
        k2 = bwd[f]
        break


    b = defun(k, b'0467a52afa8f15cfb8f0ea40365a6692')
    if b in fwd:
        print("FOUND: {} {}".format(fwd[b], k))
        k1 = fwd[b]
        k2 = k
        break
        
    fwd[f] = k
    bwd[b] = k
 ```

 finally, knowing `key=(k1, k2)` we can decrypt the flag:

 `print(defun(k1, defun(k2, rf)))`

## mlauth
### Solution


This was a fun challenge. We are given keras model, that performs some sort of classification task on given input, as authorization measure.

It's known, that alot of Deep Learning models suffer from [adversarial attacks](https://www.google.com). in a simpliest scenario, we can perform gradient ascent, modifying input image, to maximize chances of input missclasification. 

From preprocessing code 
```python
prof_h = profile.split('0x')
ip = [int(_, 16) for _ in prof_h[1:]]
ip = np.array(ip, dtype='float32')/255
# reshape profile as required by the trained model
ip = ip.reshape([1,28,28,1])
```
 
we see, that input of our network is a 1-channel 28x28 "image" with 1-byte values. So let's atack it. To do this, we can use [foolbox](https://foolbox.readthedocs.io/en/latest/):

```python
fmodel = foolbox.models.KerasModel(model, bounds=(0, 255), preprocessing=(0, 255))
attack = foolbox.attacks.L1BasicIterativeAttack(fmodel)
```

this specifies an attack, we're using L1 as a metric, while input data will be divided by 255, before supplementing it to our model. Now we can perform an attack on random image, trying to missclassify it in proper way: 
```python
d = np.random.rand(28,28,1) * 255
adversarial = attack(d, 0)
```

Only thing left is build token, that can be sent in url:
```python
profile = "".join([hex(int(t)) for t in adversarial.ravel()])
```

## GenuineCounterMode
### Statement
can you get the flag?
```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from secret import flag, key
from hashlib import sha256
from Crypto.Util.number import *
from binascii import hexlify

H = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
sessionid = b''
n = 327989969870981036659934487747327553919


def group(a, length=16):
    count = len(a) // length
    if len(a) % length != 0:
        count += 1
    return [a[i * length: (i + 1) * length] for i in range(count)]


def GHASH(ciphertext, nonce):
    assert len(nonce) == 12
    c = AES.new(key, AES.MODE_ECB).encrypt(nonce + bytes(3) + b'\x01')
    blocks = group(ciphertext)
    tag = bytes_to_long(c)
    for i, b in enumerate(blocks):
        tag += (bytes_to_long(b) * pow(bytes_to_long(H), i + 1, n)) % n
    return long_to_bytes(tag)


def encrypt(msg):
    nonce = sessionid + Random.get_random_bytes(2)
    assert len(nonce) == 12
    ctr = Counter.new(32, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(msg)
    tag = GHASH(ciphertext, nonce)
    return (nonce, ciphertext, tag)


def decrypt(nonce, ciphertext, tag):
    assert len(nonce) == 12
    assert GHASH(ciphertext, nonce) == tag
    ctr = Counter.new(32, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def main():
    global sessionid
    username = input('Enter username: ')
    sessionid = sha256(username.encode()).digest()[:10]

    while True:
        print("Menu")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[3] Exit")

        choice = input("> ")

        if choice == '1':
            msg = input('Enter message to be encrypted: ')
            if 'flag' in msg:
                print("You cant encrypt flag :(")
                continue
            c = encrypt(msg.encode())
            nonce = hexlify(c[0]).decode()
            ciphertext = hexlify(c[1]).decode()
            tag = hexlify(c[2]).decode()
            print(nonce + ':' + ciphertext + ':' + tag)
            continue

        if choice == '2':
            nonce, ciphertext, tag = input(
                'Enter message to be decrypted: ').split(':')
            nonce = long_to_bytes(int(nonce, 16))
            ciphertext = long_to_bytes(int(ciphertext, 16))
            tag = long_to_bytes(int(tag, 16))
            pt = decrypt(nonce, ciphertext, tag).decode()
            if pt == 'may i please have the flag':
                print("Congrats %s" % username)
                print("Here is your flag: %s" % flag)
            print(pt)
            continue

        if choice == '3':
            break

if __name__ == '__main__':
    main()
```
### Solution

We are given a server, that can encrypt everything, that doesn't contain word 'flag' in it. The only way to get the flag is to ask for it politely (e.g. submit properly ecrypted message `may i please have the flag`) it will return proper flag. 

We can see, that AES is used CTR mode. Essentially, that means, that AES generates a `key`, and ciphertext is just a XOR of the said `key` and plaintext. Therefore, we can easily manipulate ciphertext to modify the message: we can encrypt random message `rmsg` and then provide `encrypt(rmsg) XOR rmsg XOR "may i please have the flag"`. This would've been too easy, so we also have a `tag`, which is a function of ciphertext, and it's verified on every decription. Let's see if we can break it:

```python
H = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
n = 327989969870981036659934487747327553919

 def GHASH(ciphertext, nonce):
    assert len(nonce) == 12
    c = AES.new(key, AES.MODE_ECB).encrypt(nonce + bytes(3) + b'\x01')
    blocks = group(ciphertext)
    tag = bytes_to_long(c)
    for i, b in enumerate(blocks):
        tag += (bytes_to_long(b) * pow(bytes_to_long(H), i + 1, n)) % n
    return long_to_bytes(tag)
```

Few things to note here:
	* `c` is just a function of `nonce`
	* GHASH is a function of `ciphertext, nonce, H`. Out of this three, only H is unknown
	* `n` used in this function is prime. Which means we can compute inverse module n really easy

Let's assume that we have a message `m` less than one block (16 bytes). Then it's tag is `c + (m * H) mod n`. We want to obtain H. To do this we can obtain 2 different messages with the same `nonce` , then:

```
tag1 = c + (m1 * H) mod n
tag2 = c + (m2 * H) mod n
-----Therefore----
tag1-tag2 = (m1-m2) * H mod n
-----Therefore----
H = (tag1-tag2) * modInv(m1-m2, n)
```

Here `modInv(a, n)` is inverse module `n`. Fortunatelly, `n` us prime, therefore we can use [EGCD]{https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm} to compute inverse

Next goal: obtain two short messages with same value of nonce. Fortunatelly, `nonce` has only 2 random bytes, which means we can just spam requests to encrypt random messages, until two of them have same `nonce`. Due to birthday paradox we're expected to make only about 256 requests
```python 
from pwn import *

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
```

Now, we know H, time to retrieve the flag:
	1. Encrypt message of the same length, like "may i please have the galf"
	2. Retrieve value of `c` for GHASH: 
```python
		blocks = group(ciphertext)
	    t = 0
	    for i, b in enumerate(blocks):
	        t += (bytes_to_long(b) * pow(H, i + 1, n)) % n
	    c = itag - t
	    if c < 0:
	        c += n 
    ```
    3. Modify the ciphertext:
```python
	ciphertext = xor(ciphertext, [ord(x) for x in b"may i please have the flag\x00"])
    ciphertext = xor(ciphertext, [ord(x) for x in b"may i please have the galf\x00"])
```
	4. Calculate the tag (just use same logics as in GHASH)






