"""Tests for primality testing and prime generation."""

from __future__ import annotations

import random

from rsa_scratch import (
    generate_distinct_primes,
    generate_prime,
    is_prime_trial_division,
    is_probable_prime,
)

# A few well-known primes and composites for spot checks.
KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 97, 101, 7919, 104729, 1_000_003]
KNOWN_COMPOSITES = [0, 1, 4, 9, 15, 21, 100, 561, 1105, 1729, 1_000_000]

# Carmichael numbers: composites that fool the naive Fermat test. Miller-Rabin
# must still classify them as composite.
CARMICHAEL_NUMBERS = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041]


def test_miller_rabin_agrees_with_trial_division_on_small_numbers():
    # The strongest correctness check: exhaustive agreement with ground truth.
    for n in range(2, 5000):
        assert is_probable_prime(n) == is_prime_trial_division(n), n


def test_known_primes_classified_prime():
    for p in KNOWN_PRIMES:
        assert is_probable_prime(p), p


def test_known_composites_classified_composite():
    for c in KNOWN_COMPOSITES:
        assert not is_probable_prime(c), c


def test_carmichael_numbers_detected_as_composite():
    for c in CARMICHAEL_NUMBERS:
        assert not is_probable_prime(c), c


def test_negative_and_small_values():
    assert not is_probable_prime(-7)
    assert not is_probable_prime(0)
    assert not is_probable_prime(1)


def test_generate_prime_has_correct_bit_length_and_is_prime():
    for bits in (16, 32, 64, 128, 256):
        p = generate_prime(bits)
        assert p.bit_length() == bits
        assert is_probable_prime(p)
        assert p % 2 == 1  # primes above 2 are odd


def test_generate_prime_small_is_genuinely_prime():
    # For small bit sizes we can confirm primality deterministically.
    for _ in range(20):
        p = generate_prime(20)
        assert is_prime_trial_division(p)


def test_generate_distinct_primes_are_distinct_and_prime():
    rng = random.Random(0)  # noqa: F841 -- generation uses secrets, not this
    for _ in range(5):
        p, q = generate_distinct_primes(64)
        assert p != q
        assert is_probable_prime(p)
        assert is_probable_prime(q)
        assert p.bit_length() == 64
        assert q.bit_length() == 64
