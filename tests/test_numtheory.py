"""Tests for the number-theory primitives."""

from __future__ import annotations

import math
import random

import pytest

from rsa_scratch import extended_gcd, gcd, lcm, mod_exp, mod_inverse


def test_gcd_matches_math_gcd():
    rng = random.Random(1)
    for _ in range(500):
        a = rng.randint(0, 10**12)
        b = rng.randint(0, 10**12)
        assert gcd(a, b) == math.gcd(a, b)


def test_extended_gcd_bezout_identity():
    rng = random.Random(2)
    for _ in range(500):
        a = rng.randint(1, 10**9)
        b = rng.randint(1, 10**9)
        g, x, y = extended_gcd(a, b)
        assert g == math.gcd(a, b)
        assert a * x + b * y == g  # Bezout's identity holds exactly


def test_mod_inverse_against_brute_force():
    # For small moduli, verify mod_inverse agrees with an exhaustive search.
    for m in range(2, 60):
        for a in range(1, m):
            if math.gcd(a, m) != 1:
                with pytest.raises(ValueError):
                    mod_inverse(a, m)
                continue
            inv = mod_inverse(a, m)
            assert 0 <= inv < m
            assert (a * inv) % m == 1
            # Brute-force the unique inverse and compare.
            brute = next(x for x in range(m) if (a * x) % m == 1)
            assert inv == brute


def test_mod_inverse_rejects_non_coprime():
    with pytest.raises(ValueError):
        mod_inverse(6, 9)  # gcd(6, 9) == 3


def test_mod_exp_matches_builtin_pow():
    rng = random.Random(3)
    for _ in range(1000):
        base = rng.randint(0, 10**9)
        exp = rng.randint(0, 10**4)
        mod = rng.randint(1, 10**9) + 1
        assert mod_exp(base, exp, mod) == pow(base, exp, mod)


def test_mod_exp_negative_exponent():
    # Negative exponents go through the modular inverse.
    assert mod_exp(3, -1, 7) == mod_inverse(3, 7)
    assert (mod_exp(3, -1, 7) * 3) % 7 == 1


def test_mod_exp_large_values():
    # A stress case far beyond what naive base**exp could handle.
    assert mod_exp(7, 10**6, 1_000_000_007) == pow(7, 10**6, 1_000_000_007)


def test_lcm():
    assert lcm(4, 6) == 12
    assert lcm(0, 5) == 0
    rng = random.Random(4)
    for _ in range(200):
        a = rng.randint(1, 10**6)
        b = rng.randint(1, 10**6)
        assert lcm(a, b) == math.lcm(a, b)
