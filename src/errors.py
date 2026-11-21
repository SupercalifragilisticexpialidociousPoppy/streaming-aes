"""
Exceptions for the chunkcrypt format.

None of these ever carry plaintext or key material in their messages (PRD NFR-7).
"""


class ChunkcryptError(Exception):
    """Base class: anything that means "do not trust this stream"."""


class HeaderError(ChunkcryptError):
    """The 49-byte header is malformed, truncated, or describes something we don't support."""


class CounterOverflowError(ChunkcryptError):
    """The 32-bit chunk counter would wrap. Wrapping = nonce reuse, so we refuse instead."""


class AuthenticationError(ChunkcryptError):
    """A chunk's tag did not verify: wrong key, tampered bytes, tampered header, or wrong position."""
