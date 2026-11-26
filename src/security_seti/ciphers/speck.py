"""SPECK32/64, with a configurable number of rounds.

SPECK is an ARX block cipher (add-rotate-xor) from the NSA SIMON/SPECK family.
SPECK32/64 has a 32-bit block (two 16-bit words), a 64-bit key, and 22 rounds at
full strength. Round-reduced SPECK32 is a classic, well-studied differential
cryptanalysis target: short enough that trails are findable and biases are
measurable, real enough that the attacks are the genuine article.

Full-round test vector (22 rounds):
    key        = 1918 1110 0908 0100
    plaintext  = 6574 694c
    ciphertext = a868 42f2
"""

from __future__ import annotations

from typing import List, Tuple

WORD = 16
MASK = (1 << WORD) - 1
ALPHA = 7
BETA = 2
M = 4            # key words
FULL_ROUNDS = 22


def rol(x: int, r: int) -> int:
    r %= WORD
    return ((x << r) | (x >> (WORD - r))) & MASK


def ror(x: int, r: int) -> int:
    r %= WORD
    return ((x >> r) | (x << (WORD - r))) & MASK


def _round(x: int, y: int, k: int) -> Tuple[int, int]:
    x = (ror(x, ALPHA) + y) & MASK
    x ^= k
    y = rol(y, BETA) ^ x
    return x, y


def key_schedule(key_words: List[int], rounds: int = FULL_ROUNDS) -> List[int]:
    """``key_words`` is [K0, K1, K2, K3], K0 least significant."""
    if len(key_words) != M:
        raise ValueError("SPECK32/64 needs exactly 4 key words")
    l = [key_words[1], key_words[2], key_words[3]]
    k = [key_words[0]]
    for i in range(rounds - 1):
        l_new = ((k[i] + ror(l[i], ALPHA)) & MASK) ^ i
        l.append(l_new)
        k.append(rol(k[i], BETA) ^ l_new)
    return k[:rounds]


class Speck32:
    """A SPECK32/64 instance with a chosen round count."""

    def __init__(self, key_words: List[int], rounds: int = FULL_ROUNDS) -> None:
        self.rounds = rounds
        self.round_keys = key_schedule(key_words, rounds)

    def encrypt(self, x: int, y: int) -> Tuple[int, int]:
        for rk in self.round_keys:
            x, y = _round(x, y, rk)
        return x & MASK, y & MASK

    def encrypt_block(self, block: int) -> int:
        x, y = (block >> WORD) & MASK, block & MASK
        x, y = self.encrypt(x, y)
        return (x << WORD) | y


def speck32_encrypt(key_words: List[int], x: int, y: int,
                    rounds: int = FULL_ROUNDS) -> Tuple[int, int]:
    return Speck32(key_words, rounds).encrypt(x, y)
