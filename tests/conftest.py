"""Shared pytest fixtures.

Key generation is the slow part, so we generate a handful of keys once per test
session and reuse them everywhere.
"""

from __future__ import annotations

import pytest

from rsa_scratch import generate_keypair


@pytest.fixture(scope="session")
def keypair_512():
    return generate_keypair(512)


@pytest.fixture(scope="session", params=[512, 768, 1024])
def keypair_various(request):
    """Parametrised keypair across several modulus sizes."""
    return generate_keypair(request.param)
