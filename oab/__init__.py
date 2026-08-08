"""Operational Agent Benchmark v2."""

import sys

if sys.version_info < (3, 11):  # pragma: no cover - guard runs before any test
    raise RuntimeError(
        "operational-agent-benchmark requires Python 3.11 or newer; "
        f"this interpreter is {sys.version_info.major}.{sys.version_info.minor} "
        f"({sys.executable}). Run the suite with a supported interpreter, e.g. "
        "python3.11 -m unittest discover -s tests"
    )

__all__ = ["__version__"]
__version__ = "2.2.1"
