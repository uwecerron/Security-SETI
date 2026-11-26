"""Example agents shipped with security_seti.

* :class:`ReconAgent` — wraps a generic allow-listed command tool.
* :class:`DifferentialCryptanalysisAgent` — proposes differentials for
  round-reduced SPECK32 and *empirically measures* their probability, binding
  every result to a reproducible experiment.

They are intentionally small and readable: templates to copy, not a framework to
subclass blindly.
"""

from .recon import ReconAgent  # noqa: F401
from .cryptanalysis import DifferentialCryptanalysisAgent  # noqa: F401

__all__ = ["ReconAgent", "DifferentialCryptanalysisAgent"]
