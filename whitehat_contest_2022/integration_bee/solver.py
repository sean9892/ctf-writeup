"""
prince_integral_attack.py -- Mount an attack based on integral cryptanalysis.
"""
from bitstring import BitArray, ConstBitStream
from functools import reduce
from operator import add
import reduced_prince_cipher
from cipher import Cipher
from os import urandom


def get_nibble(bitstr, nibble_pos):
    return bitstr[nibble_pos * 4 : nibble_pos * 4 + 4]


def k1_xor_k0_prime_candidate(ciphertext_set,idx=3):
    candidates = []
    for _ in range(16):
        candidates.append({"ok": set(), "fail": set()})
    for nibble_pos in range(16):
        for guess_value in range(16):
            guess = BitArray(hex(guess_value))
            RC3_nibble = get_nibble(reduced_prince_cipher.RC[idx], nibble_pos)
            for ciphertexts in ciphertext_set:
                xor_sum = BitArray(4)
                for ciphertext in ciphertexts:
                    ciphertext_nibble = get_nibble(ciphertext, nibble_pos)
                    xor_sum ^= reduced_prince_cipher.s_layer(
                        ciphertext_nibble ^ guess ^ RC3_nibble
                    )
                if (
                    xor_sum.uint == 0
                    and guess_value not in candidates[nibble_pos]["fail"]
                ):
                    candidates[nibble_pos]["ok"].add(guess_value)
                elif xor_sum.uint != 0:
                    if guess_value in candidates[nibble_pos]["ok"]:
                        candidates[nibble_pos]["ok"].remove(guess_value)
                    candidates[nibble_pos]["fail"].add(guess_value)
    return candidates


def get_result_from_candidate(candidate):
    assert all([len(x["ok"]) for x in candidate])
    return reduce(add, [BitArray(hex(x["ok"].pop())) for x in candidate])

from pwn import *
from hashlib import sha256
from bitstring import BitArray
import os

# nc 43.201.6.137 7331
HOST = "43.201.6.137"
PORT = 7331
r = remote(HOST,PORT)

#context.log_level = 'debug'

def PoW():
    s = r.readline().decode().strip()
    x=0
    while True:
        h = sha256((s+str(x)).encode()).hexdigest()
        if h[:6]=="012345":
            break
        x+=1
    print("PoW:",x)
    r.sendline(str(x).encode())

def pts_1_active_nibble(dummy,idx):
    dummy_chr = hex(dummy)[-1]
    pts = []
    for i in range(16):
        i_chr = hex(i)[-1]
        l = [dummy_chr for _ in range(16)]
        l[idx] = i_chr
        pts.append(''.join(l))
    return tuple(pts)


def main():
    PoW()

    cipher = Cipher()

    NIBBLE_SET_CNT = 2
    
    nibs1 = set() # nibble set with 1 active nibble
    nibs2 = set() # nibble set with 4 active nibble

    pt1 = tuple()
    pt2 = tuple()


    while len(nibs1)<NIBBLE_SET_CNT:
        nibs1.add((os.urandom(1)[0]&15,os.urandom(1)[0]&15))
    for dum,i in nibs1:
        pt1 += pts_1_active_nibble(dum, i)
    print(nibs1)

    res1 = []
    for pt in pt1:
        r.recvuntil(b"0x")
        r.sendline(pt.encode())
        r.recvuntil(b"0x")
        res1.append(BitArray("0x"+r.recvline().decode()))
    
    ciphertext_set = [res1[:16],res1[16:]]
    
    candidates = k1_xor_k0_prime_candidate(ciphertext_set)
    k1_xor_k0_prime = get_result_from_candidate(candidates)
    print(f"k1 ^ k0' = 0b{k1_xor_k0_prime.bin}")

    while len(nibs2) < NIBBLE_SET_CNT:
        nibs2.add((urandom(1)[0] & 15, urandom(1)[0] & 15))
    for dum,i in nibs2:
        pt2 += pts_1_active_nibble(dum, i)

    pt2 = [cipher.m(cipher.sbox(BitArray(f'0x{pt}'), cipher.S)) for pt in pt2]

    ct2 = []
    for pt in pt2:
        r.recvuntil(b"0x")
        r.sendline(pt.hex)
        r.recvuntil(b"0x")
        ct2.append(BitArray("0x"+r.recvline(keepends=False).decode()))
    ct2 = [cipher.m(cipher.sbox(ct ^ k1_xor_k0_prime ^ cipher.RC[3], cipher.S)) for ct in ct2]

    ciphertext_set = [ct2[0:16],ct2[16:32]]

    candidates = k1_xor_k0_prime_candidate(ciphertext_set, idx=2)
    k1 = get_result_from_candidate(candidates)
    
    k0_prime = k1_xor_k0_prime^k1
    k0 = k0_prime.copy()
    k0.ror(63)

    key = k0.hex+k1.hex

    r.recvuntil(b"0x")
    r.sendline(key.encode())

    r.interactive()
    

if __name__ == "__main__":
    main()