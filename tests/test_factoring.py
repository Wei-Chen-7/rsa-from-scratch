"""Tests for the factoring attacks and key recovery."""

from __future__ import annotations

import random

import pytest

from rsa_scratch import (
    factor_semiprime,
    generate_keypair,
    pollards_rho,
    recover_private_exponent,
    trial_division,
)
from rsa_scratch.primes import is_prime_trial_division


def test_trial_division_finds_smallest_factor():
    assert trial_division(15) == 3
    assert trial_division(21) == 3
    assert trial_division(49) == 7
    assert trial_division(1_000_000) == 2


def test_trial_division_returns_none_for_primes():
    for p in (2, 3, 7, 13, 97, 7919):
        assert trial_division(p) is None


def test_trial_division_matches_definition_on_small_numbers():
    for n in range(2, 2000):
        factor = trial_division(n)
        if is_prime_trial_division(n):
            assert factor is None
        else:
            assert factor is not None
            assert n % factor == 0
            assert 1 < factor < n


def test_pollards_rho_finds_a_factor():
    rng = random.Random(11)
    # Products of two primes from a small pool.
    primes = [101, 103, 107, 7919, 104729, 1_000_003]
    for _ in range(30):
        p = rng.choice(primes)
        q = rng.choice(primes)
        n = p * q
        if p == q:
            continue
        factor = pollards_rho(n)
        assert factor is not None
        assert 1 < factor < n
        assert n % factor == 0


def test_pollards_rho_returns_none_for_primes():
    for p in (7919, 104729, 1_000_003):
        assert pollards_rho(p) is None


def test_factor_semiprime_recovers_both_primes():
    # Use real (small) RSA moduli so the attack target is authentic. Sizes are
    # kept tiny on purpose: pure-Python Pollard's rho is ~O(n^{1/4}), so even
    # 40-bit moduli finish in milliseconds while larger ones would crawl --
    # which is exactly the "key size matters" lesson.
    for bits in (24, 32, 40):
        public, private = generate_keypair(bits)
        p, q = factor_semiprime(public.n)
        assert {p, q} == {private.p, private.q}
        assert p * q == public.n


def test_recover_private_exponent_matches_real_key():
    # The full break: derive d from only the public key, by factoring.
    public, private = generate_keypair(40)
    recovered_d = recover_private_exponent(public.n, public.e)
    assert recovered_d == private.d


def test_factor_semiprime_rejects_prime():
    with pytest.raises(ValueError):
        factor_semiprime(7919)
