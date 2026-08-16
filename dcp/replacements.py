"""Deterministic validation of pre-registered Gate-3 pair replacements.

Replacement is deliberately narrow.  A started pair is never deleted.  A new
pair may point to it only when at least one branch has an independently
attested infrastructure outcome, and every link is retained in the evidence
ledger.  The terminal pair in each chain is the one used for effect inference.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from dcp.registration import (
    PAIR_REPLACEMENT_POLICY_NONE,
    PAIR_REPLACEMENT_POLICY_TRANSPORT,
)
from dcp.types import RawAttemptOutcome


@dataclass(frozen=True)
class ReplacementLedger:
    active_indices: tuple[int, ...]
    replaced_indices: tuple[int, ...]
    replacement_count: int
    infrastructure_pair_count: int
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def _branches(pair: Any, branch_names: tuple[str, str]) -> tuple[Any, Any] | None:
    try:
        return getattr(pair, branch_names[0]), getattr(pair, branch_names[1])
    except AttributeError:
        return None


def _independent_infrastructure_pair(
    pair: Any, branch_names: tuple[str, str]
) -> bool:
    branches = _branches(pair, branch_names)
    if branches is None:
        return False
    infrastructure = [
        branch
        for branch in branches
        if getattr(branch, "outcome", None)
        == RawAttemptOutcome.INFRASTRUCTURE_INVALID
    ]
    return bool(infrastructure) and all(
        getattr(branch, "infrastructure_outcome_independent", None) is True
        and getattr(branch, "utility", None) is None
        and getattr(branch, "per_unit", None) is None
        for branch in infrastructure
    )


def validate_replacement_ledger(
    pairs: Sequence[Any],
    *,
    registered_n: int,
    max_replacements: int,
    policy: str,
    branch_names: tuple[str, str],
    label: str,
) -> ReplacementLedger:
    """Validate one complete started-pair ledger and select terminal pairs.

    Pair order is part of the evidence.  A replacement must point backward to
    an independently invalid pair, and each failed pair can have at most one
    child.  If the replacement allowance is not exhausted, an infrastructure
    invalid terminal pair proves that the producer stopped too early.
    """

    errors: list[str] = []
    pair_list = list(pairs)
    if (
        not isinstance(registered_n, int)
        or isinstance(registered_n, bool)
        or registered_n < 1
    ):
        errors.append(f"{label} registered N is malformed")
    if (
        not isinstance(max_replacements, int)
        or isinstance(max_replacements, bool)
        or max_replacements < 0
    ):
        errors.append(f"{label} replacement limit is malformed")
        max_replacements = 0
    if policy not in {
        PAIR_REPLACEMENT_POLICY_NONE,
        PAIR_REPLACEMENT_POLICY_TRANSPORT,
    }:
        errors.append(f"{label} replacement policy is unsupported")

    ids: list[str] = []
    replacements: list[str] = []
    index_by_id: dict[str, int] = {}
    child_by_parent: dict[str, int] = {}
    for index, pair in enumerate(pair_list):
        pair_id = getattr(pair, "pair_id", None)
        replacement_of = getattr(pair, "replacement_of", None)
        if not isinstance(pair_id, str) or not pair_id:
            errors.append(f"{label}[{index}] pair_id is malformed")
            pair_id = f"<malformed-{index}>"
        if pair_id in index_by_id:
            errors.append(f"{label} pair ids are duplicated")
        else:
            index_by_id[pair_id] = index
        ids.append(pair_id)
        if not isinstance(replacement_of, str):
            errors.append(f"{label}[{index}].replacement_of must be a string")
            replacement_of = ""
        replacements.append(replacement_of)
        if not replacement_of:
            continue
        if policy != PAIR_REPLACEMENT_POLICY_TRANSPORT:
            errors.append(f"{label}[{index}] replacement was not registered")
        parent_index = index_by_id.get(replacement_of)
        if parent_index is None or parent_index >= index:
            errors.append(
                f"{label}[{index}] replacement_of must point to an earlier pair"
            )
            continue
        if parent_index != index - 1:
            errors.append(
                f"{label}[{index}] replacement must immediately follow its "
                "failed parent"
            )
        if replacement_of in child_by_parent:
            errors.append(f"{label} failed pair has more than one replacement")
            continue
        child_by_parent[replacement_of] = index
        if not _independent_infrastructure_pair(
            pair_list[parent_index], branch_names
        ):
            errors.append(
                f"{label}[{index}] replaces a pair without independently "
                "attested infrastructure attrition"
            )

    replacement_count = sum(bool(item) for item in replacements)
    if replacement_count > max_replacements:
        errors.append(
            f"{label} replacements {replacement_count} exceed registered maximum "
            f"{max_replacements}"
        )
    roots = [index for index, parent in enumerate(replacements) if not parent]
    if len(roots) != registered_n:
        errors.append(
            f"{label} original pair slots {len(roots)} != registered N={registered_n}"
        )

    active: list[int] = []
    replaced: list[int] = []
    for root in roots:
        current = root
        seen: set[int] = set()
        while True:
            if current in seen:
                errors.append(f"{label} replacement chain contains a cycle")
                break
            seen.add(current)
            child = child_by_parent.get(ids[current])
            if child is None:
                active.append(current)
                break
            replaced.append(current)
            current = child

    reachable = set(active) | set(replaced)
    if reachable != set(range(len(pair_list))):
        errors.append(f"{label} replacement ledger contains an orphaned pair")
    if len(active) != registered_n:
        errors.append(
            f"{label} terminal pair slots {len(active)} != registered N={registered_n}"
        )

    infrastructure_pair_count = sum(
        _independent_infrastructure_pair(pair, branch_names) for pair in pair_list
    )
    terminal_infrastructure = any(
        _independent_infrastructure_pair(pair_list[index], branch_names)
        for index in active
    )
    if terminal_infrastructure and replacement_count < max_replacements:
        errors.append(
            f"{label} stopped with replaceable infrastructure attrition before "
            "the registered replacement allowance was exhausted"
        )

    return ReplacementLedger(
        active_indices=tuple(active),
        replaced_indices=tuple(replaced),
        replacement_count=replacement_count,
        infrastructure_pair_count=infrastructure_pair_count,
        errors=tuple(dict.fromkeys(errors)),
    )


def feedback_replacement_ledger(
    pairs: Sequence[Any],
    *,
    registered_n: int,
    max_replacements: int,
    policy: str,
) -> ReplacementLedger:
    return validate_replacement_ledger(
        pairs,
        registered_n=registered_n,
        max_replacements=max_replacements,
        policy=policy,
        branch_names=("truthful", "neutral"),
        label="feedback pairs",
    )


def sham_replacement_ledger(
    pairs: Sequence[Any],
    *,
    registered_n: int,
    max_replacements: int,
    policy: str,
) -> ReplacementLedger:
    return validate_replacement_ledger(
        pairs,
        registered_n=registered_n,
        max_replacements=max_replacements,
        policy=policy,
        branch_names=("reference_null", "proposed_sham"),
        label="sham pairs",
    )
