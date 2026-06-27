"""Primality testing and random prime generation.

The headline act is the Miller-Rabin probabilistic primality test, plus a
``secrets``-backed routine for sampling primes of a requested bit length.
"""

from __future__ import annotations

import secrets

from .numtheory import mod_exp

# A small sieve of primes used to cheaply reject most composites before we
# bother running the (more expensive) Miller-Rabin rounds.
_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def _miller_rabin_round(n: int, a: int, d: int, r: int) -> bool:
    """One Miller-Rabin round with witness ``a``.

    ``n - 1 == d * 2**r`` with ``d`` odd. Returns ``True`` if ``n`` is a
    *probable* prime to this base, ``False`` if ``a`` is a witness that ``n``
    is composite.
    """
    x = mod_exp(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(r - 1):
        x = (x * x) % n
        if x == n - 1:
            return True
    return False


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test.

    Returns ``True`` if ``n`` is *probably* prime. The probability that a
    composite slips through is at most ``4**-rounds`` for random bases, so the
    default of 40 rounds gives a false-positive rate below 2**-80 -- far smaller
    than the odds of a cosmic-ray bit flip.

    Small numbers are checked exactly against the sieve, so this function is
    deterministically correct for ``n`` up to the largest small prime squared.
    """
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Now n is coprime to every small prime and bigger than all of them.

    # Write n - 1 = d * 2**r with d odd.
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        # Random witness in [2, n - 2].
        a = 2 + secrets.randbelow(n - 3)
        if not _miller_rabin_round(n, a, d, r):
            return False
    return True


def is_prime_trial_division(n: int) -> bool:
    """Deterministic primality by trial division.

    Exact but slow -- O(sqrt(n)). Used as ground truth in the tests to confirm
    Miller-Rabin agrees on small numbers.
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    """Generate a random probable prime with exactly ``bits`` bits.

    Uses :func:`secrets.randbits` (a CSPRNG) for the candidate, forces the top
    bit (so the value is full-width, which keeps the modulus the intended size)
    and the bottom bit (so it is odd), then rejects until Miller-Rabin accepts.
    """
    if bits < 2:
        raise ValueError("primes need at least 2 bits")
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # set top bit and make odd
        if is_probable_prime(candidate, rounds):
            return candidate


def generate_distinct_primes(bits: int, rounds: int = 40) -> tuple[int, int]:
    """Return two distinct primes of ``bits`` bits each (for p and q)."""
    p = generate_prime(bits, rounds)
    while True:
        q = generate_prime(bits, rounds)
        if q != p:
            return p, q
