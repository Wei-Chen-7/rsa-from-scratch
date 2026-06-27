"""Integer factoring -- the attack side of RSA.

RSA's secret exponent ``d`` can be recovered from the public ``(n, e)`` the
moment you can factor ``n = p * q``: knowing ``p`` and ``q`` gives ``phi`` and
then ``d = e^{-1} mod phi``. So "how hard is it to break this key?" is exactly
"how hard is it to factor ``n``?".

We provide two classical algorithms:

* :func:`trial_division` -- O(sqrt(n)); fine for toy moduli, hopeless past ~60
  bits. It exists to make the blow-up with key size visceral.
* :func:`pollards_rho` -- Pollard's rho with Brent's cycle detection; expected
  O(n^{1/4}), which crushes trial division on medium moduli.

Neither dents a real 2048-bit key. That gap -- between what these can do and what
factoring a real modulus would take -- *is* RSA's security margin.
"""

from __future__ import annotations

from .numtheory import gcd, mod_inverse
from .primes import is_probable_prime


def trial_division(n: int) -> int | None:
    """Return the smallest nontrivial factor of ``n``, or ``None`` if prime.

    Checks 2, then odd numbers up to ``sqrt(n)``. Dead simple, and its runtime
    is what makes small keys fall instantly while ~80-bit keys already crawl.
    """
    if n < 2:
        return None
    if n == 2:
        return None  # 2 is prime; its only divisor besides 1 is itself
    if n % 2 == 0:
        return 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return i
        i += 2
    return None  # no factor found => n is prime


def pollards_rho(n: int, max_iterations: int = 1_000_000) -> int | None:
    """Return a nontrivial factor of ``n`` using Pollard's rho (Brent variant).

    Returns ``None`` for primes, for 1, or if no factor is found within
    ``max_iterations`` (rho is probabilistic -- callers may retry with a
    different constant ``c``). Expected cost is ~O(n^{1/4}), so it reaches
    moduli that trial division could never touch in reasonable time.
    """
    if n < 2 or is_probable_prime(n):
        return None  # primes (incl. 2) have no nontrivial factor
    if n % 2 == 0:
        return 2

    # Brent's improvement on Floyd cycle detection, with batched gcd.
    for c in range(1, 20):  # retry with different polynomials if needed
        y, m = 2, 128
        g = q = 1
        r = 1
        x = ys = 0
        iterations = 0
        f = lambda v: (v * v + c) % n  # noqa: E731 -- terse on purpose
        while g == 1 and iterations < max_iterations:
            x = y
            for _ in range(r):
                y = f(y)
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = f(y)
                    q = (q * abs(x - y)) % n
                    iterations += 1
                g = gcd(q, n)
                k += m
            r *= 2
        if g == n:
            # Backtrack one step at a time to recover the factor.
            g = 1
            while g == 1:
                ys = f(ys)
                g = gcd(abs(x - ys), n)
        if 1 < g < n:
            return g
    return None


def factor_semiprime(n: int) -> tuple[int, int]:
    """Factor an RSA modulus ``n = p * q`` into its two prime factors.

    Tries Pollard's rho first, falling back to trial division. Raises
    :class:`ValueError` if ``n`` does not split into two factors (e.g. it is
    prime). Intended for the RSA semiprimes produced by this library.
    """
    p = pollards_rho(n)
    if p is None:
        p = trial_division(n)
    if p is None or p == n:
        raise ValueError(f"could not factor {n} (is it prime?)")
    q = n // p
    if p * q != n:
        raise ValueError(f"internal error: {p} * {q} != {n}")
    return (p, q) if p <= q else (q, p)


def recover_private_exponent(n: int, e: int) -> int:
    """Break an RSA key: recover the private exponent ``d`` from ``(n, e)``.

    This is the whole attack. Factor ``n`` to get ``p`` and ``q``, rebuild
    ``phi = (p-1)(q-1)``, then invert ``e`` modulo ``phi``.
    """
    p, q = factor_semiprime(n)
    phi = (p - 1) * (q - 1)
    return mod_inverse(e, phi)
