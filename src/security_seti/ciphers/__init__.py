"""Reference implementations of small / round-reduced ciphers to attack.

These exist so cryptanalysis agents have a real, verifiable target. Everything
here is a toy or round-reduced construction chosen because genuine differential,
linear, and structural attacks are tractable and checkable against ground truth.
"""

from .speck import Speck32, speck32_encrypt  # noqa: F401

__all__ = ["Speck32", "speck32_encrypt"]
