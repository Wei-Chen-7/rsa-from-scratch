"""Number-theory primitives used throughout the RSA implementation.

Everything here is written from first principles so the math is visible.
In production you would lean on Python's built-in ``pow(base, exp, mod)``
(which is the same algorithm, implemented in C) and on ``math.gcd`` -- but the
whole point of this project is to show the moving parts, so we spell them out.
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Greatest common divisor via the classic Euclidean algorithm."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns ``(g, x, y)`` such that ``a * x + b * y == g`` where
    ``g == gcd(a, b)``. This is what lets us invert the public exponent
    modulo phi(n) to obtain the private exponent.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    # old_r == gcd(a, b); old_s, old_t are the Bezout coefficients.
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse of ``a`` modulo ``m``.

    Returns the unique ``x`` in ``[0, m)`` with ``(a * x) % m == 1``.
    Raises :class:`ValueError` when no inverse exists (i.e. when
    ``gcd(a, m) != 1``).
    """
    if m <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {m} (gcd={g})")
    return x % m


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """Fast modular exponentiation via right-to-left binary (square-and-multiply).

    Computes ``(base ** exponent) % modulus`` in O(log exponent) multiplications
    instead of materialising the astronomically large ``base ** exponent``.

    This is exactly what ``pow(base, exponent, modulus)`` does in CPython; we
    reimplement it here to keep the project self-contained and to make the
    algorithm explicit.
    """
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        # Negative exponent => multiply the inverse |exponent| times.
        base = mod_inverse(base, modulus)
        exponent = -exponent
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:  # current low bit set -> fold base into result
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result


def lcm(a: int, b: int) -> int:
    """Least common multiple."""
    if a == 0 or b == 0:
        return 0
    return abs(a // gcd(a, b) * b)
