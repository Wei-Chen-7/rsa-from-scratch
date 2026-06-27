"""End-to-end demo: generate a key, encrypt/decrypt, sign/verify.

Run with::

    python examples/demo_encrypt_sign.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running directly without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rsa_scratch import (  # noqa: E402
    decrypt,
    encrypt,
    generate_keypair,
    sign,
    verify,
)


def main() -> None:
    print("Generating a 2048-bit RSA key pair (this takes a moment)...")
    public, private = generate_keypair(2048)
    print(f"  modulus size : {public.key_size} bits")
    print(f"  public e     : {public.e}")
    print(f"  n (truncated): {str(public.n)[:50]}...\n")

    # --- Encryption -------------------------------------------------------
    message = b"Meet me at the old bridge at midnight."
    print(f"Plaintext : {message!r}")
    ciphertext = encrypt(public, message)
    print(f"Ciphertext: {ciphertext.hex()[:64]}... ({len(ciphertext)} bytes)")
    recovered = decrypt(private, ciphertext)
    print(f"Decrypted : {recovered!r}")
    assert recovered == message
    print("  -> round-trip OK\n")

    # Encrypting twice gives different ciphertexts (randomised padding).
    c1 = encrypt(public, message)
    c2 = encrypt(public, message)
    print(f"Same plaintext, two encryptions differ: {c1 != c2}\n")

    # --- Signatures -------------------------------------------------------
    document = b"I, Alice, agree to the terms."
    signature = sign(private, document)
    print(f"Document  : {document!r}")
    print(f"Signature : {signature.hex()[:64]}... ({len(signature)} bytes)")
    print(f"verify(genuine)  -> {verify(public, document, signature)}")

    forged = b"I, Alice, agree to NOTHING."
    print(f"verify(tampered) -> {verify(public, forged, signature)}")


if __name__ == "__main__":
    main()
