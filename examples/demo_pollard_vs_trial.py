"""Demo: Pollard's rho vs. trial division on medium moduli.

Trial division costs ~O(sqrt(n)); Pollard's rho costs ~O(n^{1/4}). On small
moduli both are instant, but as the modulus grows the gap becomes enormous --
rho keeps finding factors long after trial division has become impractical.

Run with::

    python examples/demo_pollard_vs_trial.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Allow running directly without installing the package first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rsa_scratch import (  # noqa: E402
    generate_keypair,
    pollards_rho,
    trial_division,
)

# Trial division on moduli much past ~48 bits gets painfully slow, so cap it.
TRIAL_DIVISION_BIT_CAP = 48


def time_call(fn, *args):
    start = time.perf_counter()
    result = fn(*args)
    return result, time.perf_counter() - start


def main() -> None:
    print("Pollard's rho vs. trial division")
    print("================================\n")
    print(f"{'bits':>6} | {'trial division':>18} | {'Pollard rho':>14} | speedup")
    print("-" * 60)

    for bits in (32, 40, 48, 56, 64, 72):
        _, private = generate_keypair(bits)
        n = private.n

        rho_factor, t_rho = time_call(pollards_rho, n)
        assert rho_factor is not None and n % rho_factor == 0

        if bits <= TRIAL_DIVISION_BIT_CAP:
            trial_factor, t_trial = time_call(trial_division, n)
            assert trial_factor is not None and n % trial_factor == 0
            speedup = t_trial / t_rho if t_rho > 0 else float("inf")
            trial_str = f"{t_trial * 1000:>15.2f} ms"
            speedup_str = f"{speedup:>7.0f}x"
        else:
            trial_str = f"{'(skipped)':>18}"
            speedup_str = "  huge"

        print(
            f"{bits:>6} | {trial_str} | {t_rho * 1000:>11.3f} ms | {speedup_str}"
        )

    print(
        "\nPollard's rho keeps factoring well past where trial division gives "
        "up.\nNeither, of course, makes a dent in a real 2048-bit modulus -- "
        "that is the point."
    )


if __name__ == "__main__":
    main()
