"""High-level encrypt/decrypt using PKCS#1 v1.5 padding."""

from __future__ import annotations

from .keys import PrivateKey, PublicKey, rsa_decrypt_int, rsa_encrypt_int
from .padding import (
    i2osp,
    os2ip,
    pkcs1_v15_pad_encrypt,
    pkcs1_v15_unpad_encrypt,
)


def encrypt(public: PublicKey, message: bytes) -> bytes:
    """Encrypt ``message`` for the holder of ``public``'s private key.

    Pipeline: PKCS#1 v1.5 pad -> OS2IP -> raw RSA (m^e mod n) -> I2OSP.
    The ciphertext is exactly ``k`` bytes (the modulus byte length).
    """
    k = public.byte_length
    em = pkcs1_v15_pad_encrypt(message, k)
    m = os2ip(em)
    c = rsa_encrypt_int(public, m)
    return i2osp(c, k)


def decrypt(private: PrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt ``ciphertext`` and strip the PKCS#1 v1.5 padding."""
    k = private.byte_length
    if len(ciphertext) != k:
        raise ValueError(f"ciphertext must be exactly {k} bytes")
    c = os2ip(ciphertext)
    m = rsa_decrypt_int(private, c)
    em = i2osp(m, k)
    return pkcs1_v15_unpad_encrypt(em, k)


def encrypt_textbook(public: PublicKey, message: bytes) -> bytes:
    """UNSAFE textbook RSA encryption (no padding) -- for the demos only.

    Deterministic and malleable. Provided so the README/demos can show *why*
    padding matters. Do not use for anything real.
    """
    k = public.byte_length
    m = os2ip(message)
    c = rsa_encrypt_int(public, m)
    return i2osp(c, k)


def decrypt_textbook(private: PrivateKey, ciphertext: bytes, length: int) -> bytes:
    """UNSAFE textbook RSA decryption (no padding) -- for the demos only.

    ``length`` is the original message length, needed because raw RSA loses
    leading zero bytes.
    """
    c = os2ip(ciphertext)
    m = rsa_decrypt_int(private, c)
    return i2osp(m, length)
