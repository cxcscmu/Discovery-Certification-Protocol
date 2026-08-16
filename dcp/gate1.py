"""Gate 1 — is the result actually valid? (proposal §4).

Certifies that A* satisfies its outcome contract and beats the frozen baseline
by at least delta_min on the sealed private units, and that the baseline itself
sits *outside* the recovery interval (so "recovery" is not trivially the
baseline).  No challengers here — this gate is only about the main result.

This module reports *primitives*; the exact §8.4 fail-closed ordering (which,
e.g., checks baseline validity before Valid(A*)) is applied in ``dcp.verdict``.
"""

from __future__ import annotations

from dcp.registration import Registration
from dcp.stats import mean_diff_ci
from dcp.types import Gate1Evidence, Gate1Result, TriState, Validity


def evaluate_gate1(reg: Registration, ev: Gate1Evidence) -> Gate1Result:
    eps = reg.epsilon
    coverage = 1.0 - reg.alpha_main
    method = reg.ci_method

    x = float(sum(ev.astar.per_unit) / len(ev.astar.per_unit))

    up = mean_diff_ci(
        ev.astar.per_unit, ev.baseline.per_unit, coverage, method=method
    )  # A* - baseline
    down = mean_diff_ci(
        ev.baseline.per_unit, ev.astar.per_unit, coverage, method=method
    )  # baseline - A*

    utility_pass = up.lcb >= reg.delta_min
    utility_confirmed_below = up.ucb < reg.delta_min

    # baseline must fail P: UCB[mu(baseline) - mu(A*)] < -epsilon  (§4.2).
    if down.ucb < -eps:
        baseline_fails = TriState.PASS
    elif down.lcb >= -eps:
        baseline_fails = TriState.FAIL  # baseline actually satisfies P
    else:
        baseline_fails = TriState.INCONCLUSIVE
    baseline_satisfies_p = baseline_fails == TriState.FAIL

    # result_validity strictly tracks Valid(A*) (§4.3).
    if ev.astar.validity == Validity.INVALID:
        result_validity = TriState.FAIL
    elif ev.astar.validity == Validity.UNRESOLVED:
        result_validity = TriState.INCONCLUSIVE
    else:
        result_validity = TriState.PASS

    reason = (
        f"x={x:.4f}, effect LCB={up.lcb:.4f} (delta_min={reg.delta_min}), "
        f"baseline_fails_P={baseline_fails.value}"
    )

    return Gate1Result(
        result_validity=result_validity,
        astar_validity=ev.astar.validity,
        baseline_validity=ev.baseline.validity,
        x=x,
        effect_mean=up.mean,
        effect_lcb=up.lcb,
        effect_ucb=up.ucb,
        utility_pass=utility_pass,
        utility_confirmed_below=utility_confirmed_below,
        baseline_fails_p=baseline_fails,
        baseline_satisfies_p=baseline_satisfies_p,
        reason=reason,
    )
