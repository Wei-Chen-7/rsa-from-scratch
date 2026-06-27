# RSA from scratch

[![CI](https://github.com/wei-chen-7/rsa-from-scratch/actions/workflows/ci.yml/badge.svg)](https://github.com/wei-chen-7/rsa-from-scratch/actions/workflows/ci.yml)

A from-first-principles implementation of **RSA public-key cryptography** in pure
Python — standard library only, no `cryptography`, no `pycryptodome`, nothing but
`secrets`, `hashlib`, and integer arithmetic. It exists to make the number theory
behind RSA legible: every moving part (primality testing, key generation, modular
exponentiation, padding, signatures, and the factoring attacks that break it) is
written out and tested rather than imported.

> ### ⚠️ Do not use this for real security
>
> This code is **educational**. It has not been audited; it makes **no** attempt
> at side-channel (timing/cache) resistance; its PKCS#1 v1.5 decryption raises
> distinguishable errors, which is a textbook [Bleichenbacher
> oracle](https://en.wikipedia.org/wiki/Adaptive_chosen-ciphertext_attack); and
> its randomness, while sourced from `secrets`, has not been validated for
> production use. For anything that actually needs to be secure, use a vetted
> library such as [`cryptography`](https://cryptography.io). The value here is in
> *understanding*, not in *deploying*.

---

## Quick start

```bash
git clone https://github.com/wei-chen-7/rsa-from-scratch
cd rsa-from-scratch
python -m pip install -e ".[dev]"   # only dependency is pytest, for the tests
pytest                              # run the full suite

python examples/demo_encrypt_sign.py     # encrypt/decrypt + sign/verify
python examples/demo_break_small_key.py  # break tiny keys by factoring
python examples/demo_pollard_vs_trial.py # Pollard's rho vs trial division
```

Library usage:

```python
from rsa_scratch import generate_keypair, encrypt, decrypt, sign, verify

public, private = generate_keypair(2048)

ct = encrypt(public, b"hello")
assert decrypt(private, ct) == b"hello"

sig = sign(private, b"hello")
assert verify(public, b"hello", sig)
```

---

## Project layout

```
rsa_scratch/
  numtheory.py   gcd, extended Euclidean algorithm, modular inverse, fast modexp
  primes.py      Miller-Rabin primality test, secure random prime generation
  keys.py        key generation (n, phi, e, d) + raw RSA primitives with CRT
  padding.py     PKCS#1 v1.5 padding (encryption & signature) + I2OSP/OS2IP
  cipher.py      encrypt / decrypt (padded, and an explicit "textbook" mode)
  signature.py   RSASSA-PKCS1-v1_5 sign / verify over SHA-256
  factoring.py   trial division, Pollard's rho, and full private-key recovery
tests/           pytest suite covering every module
examples/        runnable demos
```

---

## How RSA works (the math)

RSA is built on **modular arithmetic** and one piece of asymmetry: multiplying
two large primes is easy, but factoring their product back apart is hard.

### 1. Key generation

1. Pick two large random primes `p` and `q` (here, each half the modulus size).
   We find them with [`generate_prime`](rsa_scratch/primes.py): sample random
   odd numbers of the right bit length and test each with Miller-Rabin until one
   passes.
2. Compute the **modulus** `n = p · q`. This is public.
3. Compute **Euler's totient** `φ(n) = (p − 1)(q − 1)` — the count of integers in
   `[1, n)` that are coprime to `n`. This is secret (it leaks `p` and `q`).
4. Choose a **public exponent** `e` coprime to `φ(n)`. We use `65537`: it is
   prime and has only two set bits, so encryption is fast.
5. Compute the **private exponent** `d = e⁻¹ mod φ(n)` using the extended
   Euclidean algorithm — see [`mod_inverse`](rsa_scratch/numtheory.py).

The public key is `(n, e)`; the private key is `(n, d)` (we also keep `p`, `q`
and CRT helpers).

### 2. Encryption and decryption

The core operations are just modular exponentiation:

```
encrypt:  c = m^e mod n
decrypt:  m = c^d mod n
```

These invert each other because `e·d ≡ 1 (mod φ(n))`, and by Euler's theorem
`m^(e·d) ≡ m (mod n)` for every `m` in `[0, n)`. We compute the powers with
**square-and-multiply** ([`mod_exp`](rsa_scratch/numtheory.py)) so the work is
`O(log e)` multiplications instead of forming the astronomically huge `m^e`.
Decryption uses the **Chinese Remainder Theorem** (working mod `p` and `q`
separately) for a ~3–4× speedup.

### 3. Signatures

Signing is the same trapdoor run "backwards": only the holder of `d` can produce
an `s` with `s^e mod n` equal to a known, structured value. We sign a SHA-256
hash of the message (via EMSA-PKCS1-v1_5 encoding) so signatures are short and
the message can't be forged from the hash.

```
sign:    s = EMSA(SHA256(m))^d mod n
verify:  recompute EMSA(SHA256(m)) and check it equals s^e mod n
```

### 4. Why padding matters (textbook RSA is broken)

Raw "textbook" RSA — encrypting `m^e mod n` with no padding — is **insecure**,
and this repo lets you see why:

- **It is deterministic.** The same plaintext always encrypts to the same
  ciphertext, so an attacker can build a dictionary of guesses (`encrypt(public,
  "yes")`, `encrypt(public, "no")`, …) and match. The
  [`test_padding_is_randomised`](tests/test_cipher.py) test shows our padded
  scheme avoids this; the same message encrypts to two different ciphertexts.
- **It is malleable.** `Enc(m₁)·Enc(m₂) = Enc(m₁·m₂) mod n`, so ciphertexts can
  be combined into valid ciphertexts for related messages.
- **Small messages with small `e` don't even need a key.** If `m^e < n` then
  taking an ordinary integer `e`-th root of the ciphertext recovers `m`.

We implement **PKCS#1 v1.5** padding to fix the first two: it prepends a random,
non-zero pad so encryption is non-deterministic and messages have rigid
structure. PKCS#1 v1.5 is itself dated — its *decryption* padding is vulnerable
to Bleichenbacher's adaptive chosen-ciphertext attack when an oracle reveals
whether padding is valid; **OAEP** is the modern replacement. We chose v1.5
because it is the most readable scheme to learn from, and we flag its weakness in
the code and here. The unsafe textbook mode is preserved as
`encrypt_textbook` / `decrypt_textbook` purely so the demos can exhibit the
attacks.

---

## The security argument, and the quantum connection

### Why is RSA secure?

The public key hands the world `n` and `e`. To recover the private exponent `d`
you need `φ(n) = (p−1)(q−1)`, and to get `φ(n)` you need `p` and `q` — i.e. you
need to **factor `n`**. RSA's security therefore rests on the **integer
factorization problem**: there is no known efficient *classical* algorithm to
factor a product of two large random primes. The best known methods (the General
Number Field Sieve) run in sub-exponential but super-polynomial time; factoring a
2048-bit modulus is comfortably beyond all the computing power on Earth.

Crucially, the security comes from this *computational hardness*, not from hiding
the algorithm. Everything about how RSA works is public — only the factorization
of your particular `n` is secret.

You can **watch this argument hold and break** in
[`examples/demo_break_small_key.py`](examples/demo_break_small_key.py): it
factors deliberately tiny moduli, rebuilds `d` from only the public key, and
times how that cost explodes with bit length. Trial division costs roughly
`2^(b/2)` for a `b`-bit modulus — every extra bit makes it harder, and the curve
goes vertical long before real key sizes. That blow-up *is* the security margin.

### The quantum connection — Shor's algorithm

The hardness of factoring is only a *classical* fact. In 1994 Peter Shor showed
that a sufficiently large **quantum computer** can factor integers in
**polynomial time** using the quantum Fourier transform to find the period of
`a^x mod n`. Shor's algorithm doesn't just chip away at RSA — it collapses the
problem from sub-exponential to polynomial, which would break RSA (and
Diffie-Hellman, and elliptic-curve crypto) outright.

The catch is hardware: Shor's algorithm needs many thousands of stable,
error-corrected logical qubits, far beyond today's noisy machines. But the
existence of the algorithm is why the field is migrating to **post-quantum
cryptography** (lattice-based schemes like ML-KEM/Kyber and ML-DSA/Dilithium),
whose security rests on problems with no known efficient quantum attack.

> 🔗 **See it in action.** To understand *how* a quantum computer factors `n` —
> period finding, the quantum Fourier transform, and a runnable simulation of
> Shor's algorithm — pair this project with a companion **quantum-algorithms**
> project. This repo shows you the lock RSA builds out of factoring; that one
> shows you the quantum key that opens it.

---

## What's implemented

| Area | Function(s) | Notes |
| --- | --- | --- |
| Modular inverse | `mod_inverse`, `extended_gcd` | tested against brute force |
| Fast exponentiation | `mod_exp` | square-and-multiply; tested vs `pow` |
| Primality | `is_probable_prime` | Miller-Rabin, 40 rounds by default |
| Prime generation | `generate_prime` | `secrets`-backed CSPRNG |
| Key generation | `generate_keypair` | `n`, `φ`, `e`, `d`, CRT params |
| Encryption | `encrypt` / `decrypt` | PKCS#1 v1.5 padded |
| Signatures | `sign` / `verify` | RSASSA-PKCS1-v1_5 + SHA-256 |
| Attacks | `trial_division`, `pollards_rho` | recover `d` from `(n, e)` |

### Stretch goals included

- **Pollard's rho** factoring (Brent's cycle-detection variant) — see
  `factoring.py`. The demo
  [`demo_pollard_vs_trial.py`](examples/demo_pollard_vs_trial.py) shows it
  beating trial division by orders of magnitude on medium moduli.
- **CRT-based decryption** for speed, and notes on **constant-time** concerns
  (this implementation is *not* constant-time, and the code says where that
  bites).

---

## Testing

```bash
pytest          # full suite
pytest -v       # verbose
```

The suite validates, among other things:

- **Round-trips:** `decrypt(encrypt(m)) == m` and `verify(sign(m))` for many
  random messages across several key sizes (512/768/1024-bit).
- **Miller-Rabin correctness:** exhaustive agreement with a deterministic
  trial-division check for every `n` below 5000, plus Carmichael numbers
  (composites that fool the naive Fermat test) correctly rejected.
- **Modular inverse:** agreement with an exhaustive brute-force search, and the
  Bézout identity `a·x + b·y = gcd(a, b)` for `extended_gcd`.
- **Fast modexp:** agreement with Python's built-in `pow(base, exp, mod)`.
- **The attack works:** `recover_private_exponent(n, e)` reproduces the real `d`
  for small keys by factoring `n`.

CI runs the suite on Python 3.9–3.12 on every push via GitHub Actions.

---

## License

[MIT](LICENSE). Educational use encouraged; production use strongly discouraged
(see the warning at the top).
