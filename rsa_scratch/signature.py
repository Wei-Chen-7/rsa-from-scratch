"""Digital signatures: RSASSA-PKCS1-v1_5 over SHA-256.

Signing is "decryption with the private key" of a deterministically padded hash;
verification is "encryption with the public key" followed by checking that the
recovered structure matches what we expected. Because only the private-key holder
can produce ``s`` with ``s^e mod n == EM``, a valid signature authenticates the
message.
"""

from __future__ import annotations

import hmac

from .keys import PrivateKey, PublicKey, rsa_decrypt_int, rsa_encrypt_int
from .padding import emsa_pkcs1_v15_encode, i2osp, os2ip


def sign(private: PrivateKey, message: bytes) -> bytes:
    """Produce a signature over ``message``.

    EMSA-PKCS1-v1_5 encode -> OS2IP -> raw RSA with the private exponent
    (``EM^d mod n``) -> I2OSP. The signature is ``k`` bytes.
    """
    k = private.byte_length
    em = emsa_pkcs1_v15_encode(message, k)
    m = os2ip(em)
    s = rsa_decrypt_int(private, m)  # signing == private-key transform
    return i2osp(s, k)


def verify(public: PublicKey, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` is valid for ``message`` under ``public``.

    Recompute the expected encoding and compare it (in constant time) against the
    encoding recovered from the signature. Any structural or length problem makes
    verification fail closed.
    """
    k = public.byte_length
    if len(signature) != k:
        return False
    s = os2ip(signature)
    if not 0 <= s < public.n:
        return False
    m = rsa_encrypt_int(public, s)  # verifying == public-key transform
    try:
        recovered = i2osp(m, k)
    except ValueError:
        return False
    expected = emsa_pkcs1_v15_encode(message, k)
    # Constant-time compare to avoid leaking how much of the encoding matched.
    return hmac.compare_digest(recovered, expected)
