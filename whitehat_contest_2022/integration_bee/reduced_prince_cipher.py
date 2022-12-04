"""
reduced_prince_cipher.py -- Implementation for 4-round PRINCE cipher.
"""

import numpy as np
from bitstring import BitArray
from scipy.linalg import block_diag
from typing import Tuple

RC = [
    BitArray("0xa118b13fdbb96e94"),
    BitArray("0x152ee3dc6daba45f"),
    BitArray("0x3d12266c16989530"),
    BitArray("0x3aafecc111132730"),
]

M0 = np.array([[0, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]])
M1 = np.array([[1, 0, 0, 0], [0, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]])
M2 = np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 0], [0, 0, 0, 1]])
M3 = np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 0]])
M_hat0 = np.vstack(
    (
        np.hstack((M0, M1, M2, M3)),
        np.hstack((M1, M2, M3, M0)),
        np.hstack((M2, M3, M0, M1)),
        np.hstack((M3, M0, M1, M2)),
    )
)
#original
M_hat1 = np.vstack(
    (
        np.hstack((M1, M2, M3, M0)),
        np.hstack((M2, M3, M0, M1)),
        np.hstack((M3, M0, M1, M2)),
        np.hstack((M0, M1, M2, M3)),
    )
)
M_prime = block_diag(M_hat0, M_hat1, M_hat1, M_hat0)


def expand_key(key: BitArray) -> Tuple[BitArray, BitArray, BitArray]:
    """
    Key expansion for PRINCE cipher.

    Params
    ------
    - key: BitArray
      - 128-bit key to expand. Its length must equal to 128 bits.
    """
    assert len(key) == 128
    key0 = key[:64].copy()
    rotated = key0.copy()
    rotated.ror(1)
    key1 = key[64:].copy()
    key0_prime = rotated ^ (key0 >> 63)
    return key0, key0_prime, key1


def s_layer(state: BitArray) -> BitArray:
    """
    Substitution layer for PRINCE cipher.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply the substitution. Its length must be a
        multiple of 4.
    """
    assert len(state) % 4 == 0
    sbox = [
        0xB,
        0xF,
        0x3,
        0x2,
        0xA,
        0xC,
        0x9,
        0x1,  # 01234567
        0x6,
        0x7,
        0x8,
        0x0,
        0xE,
        0x5,
        0xD,
        0x4,
    ]  # 89abcdef
    result = BitArray()
    for nibble in state.cut(4):
        result.append(BitArray(hex(sbox[nibble.uint])))
    return result


def inverse_s_layer(state: BitArray) -> BitArray:
    """
    Inverse substitution layer for PRINCE cipher.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply the inverse substitution. Its length must be
        a multiple of 4.
    """
    assert len(state) % 4 == 0
    sbox = [
        0xB,
        0x7,
        0x3,
        0x2,
        0xF,
        0xD,
        0x8,
        0x9,  # 01234567
        0xA,
        0x6,
        0x4,
        0x0,
        0x5,
        0xE,
        0xC,
        0x1,
    ]  # 89abcdef
    result = BitArray()
    for nibble in state.cut(4):
        result.append(BitArray(hex(sbox[nibble.uint])))
    return result


def shift_rows(state: BitArray) -> BitArray:
    """
    Row shift operaton for M-layer.

    Params
    ------
    - state: BitArray
      - A state bit-array to shift rows. Its length must equal to 64 bits.
    """
    assert len(state) == 64
    shift_table = [
        0x0,
        0xD,
        0xA,
        0x7,
        0x4,
        0x1,
        0xE,
        0xB,  # 01234567
        0x8,
        0x5,
        0x2,
        0xF,
        0xC,
        0x9,
        0x6,
        0x3,
    ]  # 89abcdef
    result_nibbles = [0] * 16
    for i, nibble in enumerate(state.cut(4)):
        result_nibbles[shift_table[i]] = nibble.copy()
    return BitArray().join(result_nibbles)


def inverse_shift_rows(state: BitArray) -> BitArray:
    """
    Inverse row shift operaton for M-layer.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply inverse SR. Its length must equal to 64
        bits.
    """
    assert len(state) == 64
    inverse_shift_table = [
        0x0,
        0x5,
        0xA,
        0xF,
        0x4,
        0x9,
        0xE,
        0x3,  # 01234567
        0x8,
        0xD,
        0x2,
        0x7,
        0xC,
        0x1,
        0x6,
        0xB,
    ]  # 89abcdef
    result_nibbles = [0] * 16
    for i, nibble in enumerate(state.cut(4)):
        result_nibbles[inverse_shift_table[i]] = nibble.copy()
    return BitArray().join(result_nibbles)


def m_prime_layer(state: BitArray) -> BitArray:
    """
    Matrix multiplication layer (M'-layer) for PRINCE cipher.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply matrix multiplications. Its length must
        equal to 64 bits.
    """
    assert len(state) == 64
    vec = np.array([bit.uint for bit in state.cut(1)])
    return BitArray((M_prime @ vec) % 2)


def m_layer(state: BitArray) -> BitArray:
    """
    Matrix multiplication and row shift layer (M-layer) for PRINCE cipher.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply M-layer. Its length must equal to 64 bits.
    """
    return shift_rows(m_prime_layer(state))


def inverse_m_layer(state: BitArray) -> BitArray:
    """
    Inverse M-layer for PRINCE cipher.

    Params
    ------
    - state: BitArray
      - A state bit-array to apply inverse M-layer. Its length must equal to 64
        bits.
    """
    return m_prime_layer(inverse_shift_rows(state))


def encrypt(plaintext: BitArray, key: BitArray) -> BitArray:
    """
    Encrypt a block using 4-round PRINCE cipher.

    Params
    ------
    - plaintext: BitArray
      - A plaintext block to encrypt. The length must equal to 64 bits.
    - key: BitArray
      - 128-bit key for encryption. The length must equal to 128 bits.
    """
    assert len(plaintext) == 64
    assert len(key) == 128
    key0, key0_prime, key1 = expand_key(key)
    state = plaintext.copy()

    # whitening
    state ^= key0

    # round 1
    state ^= key1
    state ^= RC[0]

    # round 2
    state = s_layer(state)
    state = m_layer(state)
    state ^= RC[1]
    state ^= key1

    # middle layer
    state = s_layer(state)
    state = m_prime_layer(state)
    state = inverse_s_layer(state)

    # round 3
    state ^= RC[2]
    state ^= key1
    state = inverse_m_layer(state)
    state = inverse_s_layer(state)

    # round 4
    state ^= RC[3]
    state ^= key1

    # whitening
    state ^= key0_prime
    return state