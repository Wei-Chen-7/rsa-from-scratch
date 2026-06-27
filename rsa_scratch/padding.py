"""PKCS#1 v1.5 padding (RFC 8017) and the integer<->octet-string conversions.

Padding is the difference between "textbook RSA" (a fun toy that is dangerously
insecure -- see the README) and something that resists the obvious attacks.
Two padding schemes live here:

* **EME-PKCS1-v1_5** (block type 0x02) for *encryption*. It mixes in random
  bytes so that encrypting the same message twice yields different ciphertexts,
  defeating the trivial dictionary attack on textbook RSA.
* **EMSA-PKCS1-v1_5** (block type 0x01) for *signatures*. It is deterministic
  and binds a hash of the message into a rigid structure.

PKCS#1 v1.5 encryption padding is known to be vulnerable to Bleichenbacher's
adaptive chosen-ciphertext attack when an oracle leaks padding validity; OAEP is
the modern alternative. We implement v1.5 because it is the most legible scheme
to learn from, and we say so loudly here and in the README.
"""

from __future__ import annotations

import hashlib
import secrets

# DER-encoded DigestInfo prefix for SHA-256, per RFC 8017 section 9.2.
# T = prefix || H, where H is the 32-byte SHA-256 digest.
_SHA256_DIGEST_INFO_PREFIX = bytes(
    [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    ]
)


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String primitive (RFC 8017): big-endian, fixed width."""
    if x < 0 or x >= 256**length:
        raise ValueError("integer too large for the requested octet length")
    return x.to_bytes(length, byteorder="big")


def os2ip(octets: bytes) -> int:
    """Octet-String-to-Integer primitive (RFC 8017): big-endian."""
    return int.from_bytes(octets, byteorder="big")


def pkcs1_v15_pad_encrypt(message: bytes, k: int) -> bytes:
    """Apply EME-PKCS1-v1_5 encryption padding.

    ``k`` is the modulus length in bytes. Produces::

        EM = 0x00 || 0x02 || PS || 0x00 || M

    where ``PS`` is at least 8 random *non-zero* bytes. The random padding is
    what makes the scheme non-deterministic.
    """
    m_len = len(message)
    if m_len > k - 11:
        raise ValueError(
            f"message too long: {m_len} bytes, max {k - 11} for a {k}-byte modulus"
        )
    ps_len = k - m_len - 3
    # Build PS from non-zero random bytes (0x00 is the separator, so PS may not
    # contain it).
    ps = bytearray()
    while len(ps) < ps_len:
        chunk = secrets.token_bytes(ps_len - len(ps))
        ps.extend(b for b in chunk if b != 0)
    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def pkcs1_v15_unpad_encrypt(padded: bytes, k: int) -> bytes:
    """Strip EME-PKCS1-v1_5 padding, returning the original message.

    Raises :class:`ValueError` on any structural problem. NOTE: a real decryptor
    must avoid leaking *which* check failed (timing or error content), or it
    becomes a Bleichenbacher oracle. This educational version raises plainly.
    """
    if len(padded) != k or k < 11:
        raise ValueError("invalid encryption block length")
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("invalid padding header (expected 0x00 0x02)")
    # Find the 0x00 separator that ends PS.
    sep_index = padded.find(b"\x00", 2)
    if sep_index < 0:
        raise ValueError("padding separator not found")
    ps = padded[2:sep_index]
    if len(ps) < 8:
        raise ValueError("padding string too short (must be >= 8 bytes)")
    return padded[sep_index + 1 :]


def emsa_pkcs1_v15_encode(message: bytes, k: int) -> bytes:
    """Build the EMSA-PKCS1-v1_5 signature encoding over SHA-256(message).

    Produces::

        EM = 0x00 || 0x01 || PS || 0x00 || T

    where ``PS`` is ``0xFF`` filler (at least 8 bytes) and ``T`` is the
    DER ``DigestInfo`` wrapping the SHA-256 digest. Unlike encryption padding
    this is fully deterministic.
    """
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    t_len = len(t)
    if k < t_len + 11:
        raise ValueError("modulus too small for a SHA-256 PKCS#1 v1.5 signature")
    ps = b"\xff" * (k - t_len - 3)
    return b"\x00\x01" + ps + b"\x00" + t
