"""Tests for PKCS#1 v1.5 encryption / decryption round-trips."""

from __future__ import annotations

import os
import random

import pytest

from rsa_scratch import decrypt, encrypt
from rsa_scratch.padding import (
    pkcs1_v15_pad_encrypt,
    pkcs1_v15_unpad_encrypt,
)


def test_round_trip_many_random_messages(keypair_various):
    public, private = keypair_various
    max_len = public.byte_length - 11
    rng = random.Random(7)
    for _ in range(25):
        length = rng.randint(0, max_len)
        message = os.urandom(length)
        ciphertext = encrypt(public, message)
        assert len(ciphertext) == public.byte_length
        assert decrypt(private, ciphertext) == message


def test_empty_message_round_trip(keypair_512):
    public, private = keypair_512
    assert decrypt(private, encrypt(public, b"")) == b""


def test_padding_is_randomised(keypair_512):
    # Encrypting the same message twice must yield different ciphertexts,
    # because the PKCS#1 v1.5 padding string is random. This is the property
    # textbook RSA lacks.
    public, _ = keypair_512
    message = b"attack at dawn"
    c1 = encrypt(public, message)
    c2 = encrypt(public, message)
    assert c1 != c2


def test_message_too_long_is_rejected(keypair_512):
    public, _ = keypair_512
    too_long = b"x" * (public.byte_length - 10)  # exceeds k - 11
    with pytest.raises(ValueError):
        encrypt(public, too_long)


def test_decrypt_rejects_wrong_length(keypair_512):
    _, private = keypair_512
    with pytest.raises(ValueError):
        decrypt(private, b"too short")


def test_pad_unpad_unit_round_trip():
    k = 64
    for length in (0, 1, 10, k - 11):
        message = os.urandom(length)
        em = pkcs1_v15_pad_encrypt(message, k)
        assert len(em) == k
        assert em[0] == 0x00 and em[1] == 0x02
        assert pkcs1_v15_unpad_encrypt(em, k) == message


def test_unpad_rejects_bad_header():
    k = 64
    bad = b"\x00\x01" + b"\xff" * 40 + b"\x00" + b"data" * 5
    with pytest.raises(ValueError):
        pkcs1_v15_unpad_encrypt(bad[:k], k)
