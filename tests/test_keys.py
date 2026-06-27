"""Tests for key generation and the raw RSA integer primitives."""

from __future__ import annotations

import random

import pytest

from rsa_scratch import (
    generate_keypair,
    is_probable_prime,
    rsa_decrypt_int,
    rsa_encrypt_int,
)


def test_keypair_structural_invariants(keypair_512):
    public, private = keypair_512
    # n is the product of the two stored primes.
    assert private.p * private.q == private.n
    assert public.n == private.n
    # Both factors are prime and distinct.
    assert is_probable_prime(private.p)
    assert is_probable_prime(private.q)
    assert private.p != private.q
    # e and d are inverses modulo phi(n).
    phi = (private.p - 1) * (private.q - 1)
    assert (public.e * private.d) % phi == 1
    # CRT parameters are internally consistent.
    assert private.dp == private.d % (private.p - 1)
    assert private.dq == private.d % (private.q - 1)
    assert (private.qinv * private.q) % private.p == 1


def test_key_size_matches_request():
    for bits in (256, 512, 1024):
        public, private = generate_keypair(bits)
        assert public.key_size == bits
        assert private.key_size == bits
        assert public.byte_length == (bits + 7) // 8


def test_raw_rsa_int_round_trip(keypair_512):
    public, private = keypair_512
    rng = random.Random(42)
    for _ in range(50):
        m = rng.randrange(0, public.n)
        c = rsa_encrypt_int(public, m)
        assert rsa_decrypt_int(private, c) == m


def test_raw_rsa_rejects_out_of_range(keypair_512):
    public, private = keypair_512
    with pytest.raises(ValueError):
        rsa_encrypt_int(public, public.n)  # m must be < n
    with pytest.raises(ValueError):
        rsa_encrypt_int(public, -1)
    with pytest.raises(ValueError):
        rsa_decrypt_int(private, private.n)


def test_custom_public_exponent():
    public, private = generate_keypair(512, e=3)
    assert public.e == 3
    phi = (private.p - 1) * (private.q - 1)
    assert (3 * private.d) % phi == 1


def test_invalid_parameters():
    with pytest.raises(ValueError):
        generate_keypair(8)  # too small
    with pytest.raises(ValueError):
        generate_keypair(512, e=4)  # even exponent
    with pytest.raises(ValueError):
        generate_keypair(512, e=1)  # too small exponent
