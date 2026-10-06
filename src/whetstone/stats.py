"""Small interval and test helpers (no scipy). Used by the adaptive-attacker experiment summary."""
from __future__ import annotations

import math


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """95% Wilson score interval for k successes of n."""
    if n == 0:
        return [0.0, 1.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def _binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1))


def _bisect(f, lo: float = 0.0, hi: float = 1.0) -> float:
    for _ in range(80):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if f(mid) else (lo, mid)
    return (lo + hi) / 2


def exact_ci(k: int, n: int, alpha: float = 0.05) -> list[float]:
    """Exact (Clopper-Pearson) two-sided interval, by bisection on the binomial tail."""
    if n == 0:
        return [0.0, 1.0]
    lo = 0.0 if k == 0 else _bisect(lambda p: 1 - _binom_cdf(k - 1, n, p) < alpha / 2)
    hi = 1.0 if k == n else _bisect(lambda p: _binom_cdf(k, n, p) > alpha / 2)
    return [round(lo, 4), round(hi, 4)]


def rate(k: int, n: int) -> dict:
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else 0.0,
            "wilson95": wilson(k, n), "exact95": exact_ci(k, n)}


def fisher_exact_two_sided(a: int, n1: int, b: int, n2: int) -> float:
    """Two-sided Fisher exact p-value for a/n1 versus b/n2 successes."""
    total, s = n1 + n2, a + b

    def pmf(x: int) -> float:
        return math.comb(n1, x) * math.comb(n2, s - x) / math.comb(total, s)

    lo, hi = max(0, s - n2), min(n1, s)
    p_obs = pmf(a)
    return round(min(1.0, sum(pmf(x) for x in range(lo, hi + 1) if pmf(x) <= p_obs * (1 + 1e-9))), 6)
