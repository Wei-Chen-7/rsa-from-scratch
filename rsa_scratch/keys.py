"""RSA key generation.

A key pair is built from two random primes ``p`` and ``q``:

    n   = p * q                  (the modulus -- public)
    phi = (p - 1) * (q - 1)      (Euler's totient of n -- secret)
    e   = 65537                  (public exponent, coprime to phi)
    d   = e^{-1} mod phi         (private exponent)

The security rests on the fact that recovering ``d`` from the public ``(n, e)``
is (as far as anyone knows publicly) as hard as factoring ``n`` -- and factoring
a large ``n`` is infeasible for classical computers.
"""

from __future__ import annotations

from dataclasses import dataclass

from .numtheory import gcd, mod_exp, mod_inverse
from .primes import generate_prime

# 65537 (0x10001) is the standard public exponent: it is prime, so it is coprime
# to phi for essentially every key, and its binary form (10000000000000001) has
# only two set bits, making public-key operations fast.
DEFAULT_EXPONENT = 65537


@dataclass(frozen=True)
class PublicKey:
    """The public half: modulus ``n`` and public exponent ``e``."""

    n: int
    e: int

    @property
    def key_size(self) -> int:
        """Modulus size in bits."""
        return self.n.bit_length()

    @property
    def byte_length(self) -> int:
        """Modulus size in bytes (ceil), i.e. the ``k`` of PKCS#1."""
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class PrivateKey:
    """The private half.

    Stores ``p``, ``q`` and the precomputed CRT parameters so that decryption
    can use the Chinese Remainder Theorem -- roughly a 3-4x speedup over a
    single full-width exponentiation.
    """

    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int  # d mod (p - 1)
    dq: int  # d mod (q - 1)
    qinv: int  # q^{-1} mod p

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    @property
    def byte_length(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_key(self) -> PublicKey:
        return PublicKey(n=self.n, e=self.e)


def generate_keypair(
    bits: int = 2048, e: int = DEFAULT_EXPONENT
) -> tuple[PublicKey, PrivateKey]:
    """Generate an RSA key pair with a modulus of ``bits`` bits.

    ``p`` and ``q`` are sized so their bit lengths sum to ``bits`` (each gets
    half, with the odd bit going to ``p``), so that ``n = p * q`` lands at
    ``bits`` bits. We retry the prime draws in the rare cases the product comes
    out one bit short, the primes collide, or ``e`` is not coprime to phi.
    """
    if bits < 16:
        raise ValueError("key size must be at least 16 bits")
    if e < 3 or e % 2 == 0:
        raise ValueError("public exponent must be an odd integer >= 3")

    p_bits = bits - bits // 2  # gets the extra bit when `bits` is odd
    q_bits = bits // 2
    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue  # e not invertible mod phi; redraw primes
        d = mod_inverse(e, phi)
        break

    # Precompute CRT helpers for fast decryption.
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = mod_inverse(q, p)

    public = PublicKey(n=n, e=e)
    private = PrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)
    return public, private


def rsa_encrypt_int(public: PublicKey, m: int) -> int:
    """The raw RSA "trapdoor" forward direction: ``c = m^e mod n``.

    ``m`` must satisfy ``0 <= m < n``. This is the textbook primitive; real
    use must apply padding (see :mod:`rsa_scratch.padding`).
    """
    if not 0 <= m < public.n:
        raise ValueError("message representative out of range [0, n)")
    return mod_exp(m, public.e, public.n)


def rsa_decrypt_int(private: PrivateKey, c: int) -> int:
    """The raw RSA inverse direction: ``m = c^d mod n``, via CRT.

    Computing ``c^d mod n`` directly is correct; we instead compute it modulo
    ``p`` and ``q`` separately (smaller exponents, smaller moduli) and glue the
    results back together with the Chinese Remainder Theorem.
    """
    if not 0 <= c < private.n:
        raise ValueError("ciphertext representative out of range [0, n)")
    m1 = mod_exp(c, private.dp, private.p)
    m2 = mod_exp(c, private.dq, private.q)
    h = (private.qinv * (m1 - m2)) % private.p
    return m2 + h * private.q
