"""rsa_scratch -- RSA public-key cryptography from first principles.

EDUCATIONAL ONLY. This is a from-scratch, pure-standard-library implementation
written to teach the number theory behind RSA. It has not been audited, makes no
attempt at side-channel resistance, and must never be used to protect real data.
Use a vetted library (e.g. ``cryptography``) for anything that matters.
"""

from __future__ import annotations

from .cipher import (
    decrypt,
    decrypt_textbook,
    encrypt,
    encrypt_textbook,
)
from .factoring import (
    factor_semiprime,
    pollards_rho,
    recover_private_exponent,
    trial_division,
)
from .keys import (
    DEFAULT_EXPONENT,
    PrivateKey,
    PublicKey,
    generate_keypair,
    rsa_decrypt_int,
    rsa_encrypt_int,
)
from .numtheory import (
    extended_gcd,
    gcd,
    lcm,
    mod_exp,
    mod_inverse,
)
from .primes import (
    generate_distinct_primes,
    generate_prime,
    is_probable_prime,
    is_prime_trial_division,
)
from .signature import sign, verify

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # numtheory
    "gcd",
    "extended_gcd",
    "mod_inverse",
    "mod_exp",
    "lcm",
    # primes
    "is_probable_prime",
    "is_prime_trial_division",
    "generate_prime",
    "generate_distinct_primes",
    # keys
    "PublicKey",
    "PrivateKey",
    "generate_keypair",
    "rsa_encrypt_int",
    "rsa_decrypt_int",
    "DEFAULT_EXPONENT",
    # cipher
    "encrypt",
    "decrypt",
    "encrypt_textbook",
    "decrypt_textbook",
    # signature
    "sign",
    "verify",
    # factoring
    "trial_division",
    "pollards_rho",
    "factor_semiprime",
    "recover_private_exponent",
]
