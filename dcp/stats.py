"""Statistical primitives for DCP-v2.

Registered sampled-population decisions use finite-sample bounded intervals;
an exhaustive fixed finite set uses its exact enumerated mean.  Student-t is
retained only as a diagnostic primitive, not as a DCP registration option.
The zero-hit Bernoulli bound is exact Clopper-Pearson.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy import stats as _sps


@dataclass(frozen=True)
class Interval:
    """A two-sided CI on a mean (or paired mean difference)."""

    mean: float
    lcb: float
    ucb: float
    se: float
    half_width: float
    n: int
    coverage: float  # two-sided coverage actually used, i.e. 1 - alpha

    @property
    def degenerate(self) -> bool:
        """True when the interval carries no usable uncertainty (n < 2)."""
        return not np.isfinite(self.half_width)


def paired_ci(
    diffs: Sequence[float],
    coverage: float,
    *,
    method: str = "student_t",
) -> Interval:
    """CI on paired differences under an explicitly registered method.

    ``student_t`` requires at least two observations and non-zero observed
    variance.  Zero variance is *not* treated as exact for a sampled population.
    ``finite_set_exact`` is valid only when the registered claim exhaustively
    enumerates its fixed private set; its interval is the exact set mean.
    """
    if not np.isfinite(coverage) or not (0.0 < coverage < 1.0):
        raise ValueError(f"coverage must be in (0,1), got {coverage}")
    if method not in (
        "student_t",
        "finite_set_exact",
        "bounded_empirical_bernstein",
    ):
        raise ValueError(f"unknown CI method {method!r}")
    x = np.asarray(diffs, dtype=float)
    n = int(x.size)
    if n == 0:
        return Interval(
            float("nan"),
            float("-inf"),
            float("inf"),
            float("inf"),
            float("inf"),
            0,
            coverage,
        )
    if not np.all(np.isfinite(x)):
        return Interval(
            float("nan"),
            float("-inf"),
            float("inf"),
            float("inf"),
            float("inf"),
            n,
            coverage,
        )
    mean = float(np.mean(x))
    if method == "finite_set_exact":
        return Interval(mean, mean, mean, 0.0, 0.0, n, 1.0)
    if method == "bounded_empirical_bernstein":
        return bounded_empirical_bernstein_interval(x, coverage)
    if n < 2:
        return Interval(
            mean, float("-inf"), float("inf"), float("inf"), float("inf"), n, coverage
        )

    sd = float(np.std(x, ddof=1))
    se = sd / np.sqrt(n)
    if se == 0.0 or not np.isfinite(se):
        return Interval(
            mean, float("-inf"), float("inf"), float("inf"), float("inf"), n, coverage
        )

    alpha = 1.0 - coverage
    tcrit = float(_sps.t.ppf(1.0 - alpha / 2.0, df=n - 1))
    hw = tcrit * se
    return Interval(mean, mean - hw, mean + hw, se, hw, n, coverage)


def mean_diff_ci(
    a: Sequence[float],
    b: Sequence[float],
    coverage: float,
    *,
    method: str = "student_t",
) -> Interval:
    """Paired CI on mean(a) - mean(b); a and b must be aligned on the same units."""
    xa = np.asarray(a, dtype=float)
    xb = np.asarray(b, dtype=float)
    if xa.shape != xb.shape:
        raise ValueError(f"paired arrays must align: {xa.shape} vs {xb.shape}")
    return paired_ci(xa - xb, coverage, method=method)


def zero_hit_upper_bound(n_ind: int, alpha: float) -> float:
    """Exact one-sided upper bound on a Bernoulli p after observing 0 / n_ind.

    Clopper-Pearson for 0 successes:  p_upper = 1 - alpha**(1/n).  Proposal
    §5.8.  n_ind <= 0 yields the vacuous bound 1.0 (no evidence).
    """
    if not (0.0 < alpha < 1.0):
        raise ValueError(f"alpha must be in (0,1), got {alpha}")
    if n_ind <= 0:
        return 1.0
    return 1.0 - alpha ** (1.0 / n_ind)


def binomial_lower_bound(successes: int, trials: int, alpha: float) -> float:
    """Exact one-sided Clopper-Pearson lower bound for a success rate."""
    if not isinstance(successes, int) or isinstance(successes, bool):
        raise ValueError("successes must be an integer")
    if not isinstance(trials, int) or isinstance(trials, bool) or trials < 1:
        raise ValueError("trials must be an integer >= 1")
    if not 0 <= successes <= trials:
        raise ValueError("successes must satisfy 0 <= successes <= trials")
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha must be in (0,1)")
    if successes == 0:
        return 0.0
    return float(_sps.beta.ppf(alpha, successes, trials - successes + 1))


def binomial_upper_bound(successes: int, trials: int, alpha: float) -> float:
    """Exact one-sided Clopper-Pearson upper bound for a success rate."""
    if not isinstance(successes, int) or isinstance(successes, bool):
        raise ValueError("successes must be an integer")
    if not isinstance(trials, int) or isinstance(trials, bool) or trials < 1:
        raise ValueError("trials must be an integer >= 1")
    if not 0 <= successes <= trials:
        raise ValueError("successes must satisfy 0 <= successes <= trials")
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha must be in (0,1)")
    if successes == trials:
        return 1.0
    return float(_sps.beta.ppf(1.0 - alpha, successes + 1, trials - successes))


def paired_binary_interval(diffs: Sequence[float], coverage: float) -> Interval:
    """Finite-sample simultaneous CI for a paired binary mean difference.

    For discordance probabilities p10 and p01, the estimand is p10-p01.
    Bonferroni-combined exact Clopper-Pearson intervals give at least the
    requested coverage without a normal or Student-t approximation.
    """
    if not np.isfinite(coverage) or not (0.0 < coverage < 1.0):
        raise ValueError("coverage must be in (0,1)")
    values = np.asarray(diffs, dtype=float)
    n = int(values.size)
    if n == 0 or not np.all(np.isin(values, (-1.0, 0.0, 1.0))):
        return Interval(
            float("nan"),
            float("-inf"),
            float("inf"),
            float("inf"),
            float("inf"),
            n,
            coverage,
        )
    plus = int(np.sum(values == 1.0))
    minus = int(np.sum(values == -1.0))
    alpha = 1.0 - coverage
    tail = alpha / 4.0
    plus_l = binomial_lower_bound(plus, n, tail)
    plus_u = binomial_upper_bound(plus, n, tail)
    minus_l = binomial_lower_bound(minus, n, tail)
    minus_u = binomial_upper_bound(minus, n, tail)
    mean = float((plus - minus) / n)
    lcb = plus_l - minus_u
    ucb = plus_u - minus_l
    return Interval(
        mean,
        lcb,
        ucb,
        float("nan"),
        max(mean - lcb, ucb - mean),
        n,
        coverage,
    )


def bounded_empirical_bernstein_interval(
    diffs: Sequence[float],
    coverage: float,
    *,
    lower: float = -1.0,
    upper: float = 1.0,
) -> Interval:
    """Distribution-free finite-sample CI for a bounded mean.

    This is the two-sided empirical-Bernstein bound for independent values in
    ``[lower, upper]``.  It remains valid for skewed or discrete utilities and
    therefore does not spend protocol alpha through a Student-t approximation.
    """
    if not np.isfinite(coverage) or not (0.0 < coverage < 1.0):
        raise ValueError("coverage must be in (0,1)")
    if not np.isfinite(lower) or not np.isfinite(upper) or not lower < upper:
        raise ValueError("finite lower < upper bounds are required")
    values = np.asarray(diffs, dtype=float)
    n = int(values.size)
    if (
        n < 2
        or not np.all(np.isfinite(values))
        or np.any(values < lower)
        or np.any(values > upper)
    ):
        return Interval(
            float("nan") if n == 0 else float(np.mean(values)),
            float("-inf"),
            float("inf"),
            float("inf"),
            float("inf"),
            n,
            coverage,
        )
    mean = float(np.mean(values))
    variance = float(np.var(values, ddof=1))
    alpha = 1.0 - coverage
    # The empirical-Bernstein expression is one-sided.  Allocate alpha/2 to
    # each tail, hence log(2 / (alpha/2)) = log(4/alpha).
    log_term = float(np.log(4.0 / alpha))
    width = upper - lower
    half_width = float(
        np.sqrt(2.0 * variance * log_term / n)
        + 7.0 * width * log_term / (3.0 * (n - 1))
    )
    return Interval(
        mean,
        max(lower, mean - half_width),
        min(upper, mean + half_width),
        float(np.sqrt(variance / n)),
        half_width,
        n,
        coverage,
    )


def bonferroni_share(alpha_total: float, m: int) -> float:
    """Simple per-slot Bonferroni allocation a_i = alpha_total / M_max (§5.7)."""
    if m <= 0:
        raise ValueError("M_max must be positive")
    return alpha_total / m


def equivalence_verdict(diffs: Sequence[float], delta: float, alpha: float) -> str:
    """CI-position equivalence rule for sham blank-calibration (§6.3).

    Uses a two-sided (1 - alpha) CI on the paired difference and returns:

        "pass"         CI entirely inside [-delta, +delta]
        "fail"         CI lies wholly outside the band
        "inconclusive" otherwise (CI straddles a band edge)

    This is the literal rule in §6.3; "no significant difference" (a failure to
    reject the null) is deliberately NOT accepted as equivalence.
    """
    if delta <= 0:
        raise ValueError("equivalence margin delta must be > 0")
    ci = paired_ci(diffs, 1.0 - alpha, method="student_t")
    if ci.degenerate:
        return "inconclusive"
    if ci.lcb >= -delta and ci.ucb <= delta:
        return "pass"
    if ci.lcb > delta or ci.ucb < -delta:
        return "fail"
    return "inconclusive"
