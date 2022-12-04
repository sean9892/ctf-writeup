#!/usr/bin/env python3
from typing import Tuple

from bitstring import BitArray


class Cipher:
    RC = [
        BitArray("0xa118b13fdbb96e94"),
        BitArray("0x152ee3dc6daba45f"),
        BitArray("0x3d12266c16989530"),
        BitArray("0x3aafecc111132730"),
    ]

    S = (
        0xB,
        0xF,
        0x3,
        0x2,
        0xA,
        0xC,
        0x9,
        0x1,
        0x6,
        0x7,
        0x8,
        0x0,
        0xE,
        0x5,
        0xD,
        0x4,
    )

    Sinv = (
        0xB,
        0x7,
        0x3,
        0x2,
        0xF,
        0xD,
        0x8,
        0x9,
        0xA,
        0x6,
        0x4,
        0x0,
        0x5,
        0xE,
        0xC,
        0x1,
    )

    def key_expansion(self, key: BitArray) -> Tuple[BitArray, BitArray, BitArray]:
        k0 = key[0:64].copy()
        k0prime = k0.copy()
        k0prime.ror(1)
        k0prime ^= k0 >> 63
        k1 = key[64:128].copy()
        return k0, k0prime, k1

    def sbox(self, data: BitArray, box: Tuple[int]) -> BitArray:
        result = BitArray()
        for nibble in data.cut(4):
            result.append(BitArray(hex(box[int(nibble.hex, 16)])))
        return result

    def shift_rows(self, data: BitArray, inverse: bool) -> BitArray:
        result = BitArray(length=64)
        idx = 0
        for nibble in data.cut(4):
            result[idx * 4 : (idx + 1) * 4] = nibble
            idx = (idx + 5 if inverse else idx + 13) % 16
        return result

    def m0(self, data: BitArray) -> BitArray:
        result = BitArray(length=16)
        result[0] = data[4] ^ data[8] ^ data[12]
        result[1] = data[1] ^ data[9] ^ data[13]
        result[2] = data[2] ^ data[6] ^ data[14]
        result[3] = data[3] ^ data[7] ^ data[11]
        result[4] = data[0] ^ data[4] ^ data[8]
        result[5] = data[5] ^ data[9] ^ data[13]
        result[6] = data[2] ^ data[10] ^ data[14]
        result[7] = data[3] ^ data[7] ^ data[15]
        result[8] = data[0] ^ data[4] ^ data[12]
        result[9] = data[1] ^ data[5] ^ data[9]
        result[10] = data[6] ^ data[10] ^ data[14]
        result[11] = data[3] ^ data[11] ^ data[15]
        result[12] = data[0] ^ data[8] ^ data[12]
        result[13] = data[1] ^ data[5] ^ data[13]
        result[14] = data[2] ^ data[6] ^ data[10]
        result[15] = data[7] ^ data[11] ^ data[15]
        return result

    def m1(self, data: BitArray) -> BitArray:
        result = BitArray(length=16)
        result[0] = data[0] ^ data[4] ^ data[8]
        result[1] = data[5] ^ data[9] ^ data[13]
        result[2] = data[2] ^ data[10] ^ data[14]
        result[3] = data[3] ^ data[7] ^ data[15]
        result[4] = data[0] ^ data[4] ^ data[12]
        result[5] = data[1] ^ data[5] ^ data[9]
        result[6] = data[6] ^ data[10] ^ data[14]
        result[7] = data[3] ^ data[11] ^ data[15]
        result[8] = data[0] ^ data[8] ^ data[12]
        result[9] = data[1] ^ data[5] ^ data[13]
        result[10] = data[2] ^ data[6] ^ data[10]
        result[11] = data[7] ^ data[11] ^ data[15]
        result[12] = data[4] ^ data[8] ^ data[12]
        result[13] = data[1] ^ data[9] ^ data[13]
        result[14] = data[2] ^ data[6] ^ data[14]
        result[15] = data[3] ^ data[7] ^ data[11]
        return result

    def m_prime(self, data: BitArray) -> BitArray:
        result = BitArray(length=64)
        result[0:16] = self.m0(data[0:16])
        result[16:32] = self.m1(data[16:32])
        result[32:48] = self.m1(data[32:48])
        result[48:64] = self.m0(data[48:64])
        return result

    def m(self, data: BitArray) -> BitArray:
        return self.shift_rows(self.m_prime(data), inverse=False)

    def minv(self, data: BitArray) -> BitArray:
        return self.m_prime(self.shift_rows(data, inverse=True))

    def encrypt(self, pt: BitArray, key: BitArray) -> BitArray:
        assert len(pt) == 64 and len(key) == 128
        k0, k0prime, k1 = self.key_expansion(key)
        result = pt.copy()

        result ^= k0

        result ^= k1 ^ self.RC[0]

        result = self.sbox(result, self.S)
        result = self.m(result)
        result ^= k1 ^ self.RC[1]

        result = self.sbox(result, self.S)
        result = self.m_prime(result)
        result = self.sbox(result, self.Sinv)

        result ^= k1 ^ self.RC[2]
        result = self.minv(result)
        result = self.sbox(result, self.Sinv)

        result ^= k1 ^ self.RC[3]

        result ^= k0prime

        return result
