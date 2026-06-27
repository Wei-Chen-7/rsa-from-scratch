"""Demo: why key size matters.

We break deliberately tiny RSA keys by factoring the public modulus with plain
classical algorithms, recovering the private exponent and decrypting a message
*without ever being given the private key*. Then we time how the attack's cost
explodes as the modulus grows -- which is exactly the wall that keeps real
2048-bit keys safe.

Run with::

    python examples/demo_break_small_key.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Allow running directly (``python examples/demo_break_small_key.py``) without
# installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rsa_scratch import (  # noqa: E402
    encrypt_textbook,
    generate_keypair,
    mod_exp,
    recover_private_exponent,
    trial_division,
)


def break_one_key(bits: int) -> None:
    """Recover the private key for a `bits`-bit modulus by factoring it."""
    public, private = generate_keypair(bits)
    print(f"\n=== Breaking a {bits}-bit key ===")
    print(f"public (n, e) = ({public.n}, {public.e})")

    # Send a secret message using ONLY the public key (textbook RSA so the demo
    # can show full recovery; real attacks target padded ciphertexts too).
    secret = b"hi"
    ciphertext = encrypt_textbook(public, secret)

    # The attacker, holding only (n, e), factors n and rebuilds d.
    start = time.perf_counter()
    recovered_d = recover_private_exponent(public.n, public.e)
    elapsed = time.perf_counter() - start

    assert recovered_d == private.d, "recovered exponent should equal the real d"

    # Decrypt the intercepted ciphertext with the recovered exponent.
    from rsa_scratch.padding import i2osp, os2ip

    m = mod_exp(os2ip(ciphertext), recovered_d, public.n)
    cracked = i2osp(m, len(secret))

    print(f"recovered d   = {recovered_d}")
    print(f"decrypted msg = {cracked!r}")
    print(f"time to break = {elapsed * 1000:.2f} ms")


def timing_table() -> None:
    """Show how trial division blows up with modulus bit length.

    We stop at a small bit count on purpose: each extra two bits of modulus
    roughly *doubles* the work, so the table would stall within a few more rows.
    That stall is the whole lesson.
    """
    print("\n=== How trial-division factoring cost grows with key size ===")
    print(f"{'bits':>6} | {'smallest factor':>16} | {'time to factor':>16}")
    print("-" * 46)
    prev = None
    for bits in (24, 28, 32, 36, 40, 44):
        _, private = generate_keypair(bits)
        n = private.n

        t0 = time.perf_counter()
        factor = trial_division(n)
        t_trial = time.perf_counter() - t0

        growth = f"  ({t_trial / prev:.1f}x prev)" if prev and prev > 0 else ""
        print(f"{bits:>6} | {factor:>16} | {t_trial * 1000:>13.2f} ms{growth}")
        prev = t_trial

    print(
        "\nEach few extra bits multiplies the cost (~2^(b/2) work overall).\n"
        "Extrapolate to a 2048-bit modulus and the runtime dwarfs the age of the\n"
        "universe. That infeasibility -- not secrecy of the algorithm -- is RSA's\n"
        "security. (Pollard's rho reaches further; see demo_pollard_vs_trial.py.)"
    )


def main() -> None:
    print("Breaking tiny RSA keys by classical factoring")
    print("=============================================")
    for bits in (32, 48, 64):
        break_one_key(bits)
    timing_table()


if __name__ == "__main__":
    main()
