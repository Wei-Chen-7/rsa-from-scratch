"""Tests for RSASSA-PKCS1-v1_5 signing and verification."""

from __future__ import annotations

import os

from rsa_scratch import generate_keypair, sign, verify


def test_sign_verify_round_trip(keypair_various):
    public, private = keypair_various
    for _ in range(10):
        message = os.urandom(64)
        signature = sign(private, message)
        assert len(signature) == private.byte_length
        assert verify(public, message, signature)


def test_verify_rejects_tampered_message(keypair_512):
    public, private = keypair_512
    message = b"transfer $100 to alice"
    signature = sign(private, message)
    assert verify(public, message, signature)
    # Flip the message; the same signature must no longer verify.
    assert not verify(public, b"transfer $900 to alice", signature)


def test_verify_rejects_tampered_signature(keypair_512):
    public, private = keypair_512
    message = b"hello world"
    signature = bytearray(sign(private, message))
    signature[-1] ^= 0x01  # flip one bit
    assert not verify(public, message, bytes(signature))


def test_verify_rejects_wrong_key(keypair_512):
    _, private = keypair_512
    other_public, _ = generate_keypair(512)
    message = b"signed by the wrong key"
    signature = sign(private, message)
    assert not verify(other_public, message, signature)


def test_verify_rejects_bad_length(keypair_512):
    public, _ = keypair_512
    assert not verify(public, b"msg", b"\x00" * 3)


def test_signature_is_deterministic(keypair_512):
    # EMSA-PKCS1-v1_5 has no randomness, so signing is deterministic.
    _, private = keypair_512
    message = b"deterministic"
    assert sign(private, message) == sign(private, message)
