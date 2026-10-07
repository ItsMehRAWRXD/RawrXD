from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class FailureSignal:
    """Verifier/test/reverse signal that explains why the previous attempt failed."""

    kind: str
    detail: str = ""
    failed_claim: str = ""
    severity: float = 1.0

    @property
    def fingerprint(self) -> str:
        raw = f"{self.kind}|{self.failed_claim}|{self.detail}".encode("utf-8", "replace")
        return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True)
class GenerationProfile:
    """
    A request-local generation genome.

    Polymorphism is explicit: each retry receives a different profile fingerprint.
    Nothing here mutates persistent model weights.
    """

    strategy: str = "direct"
    specialist: str = "generalist"
    temperature: float = 0.20
    top_p: float = 0.90
    candidate_count: int = 1
    reverse_depth: int = 1
    counterexample_budget: int = 1
    invariant_budget: int = 1
    blocking_passes: int = 3
    queue_policy: str = "Q_BLOCKING"
    mutation_nonce: int = 0

    def payload(self) -> Dict[str, object]:
        return asdict(self)

    @property
    def fingerprint(self) -> str:
        raw = json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]


class RepeatTuner:
    """
    Failure-directed repeat tuner.

    WRONG != rerun same generation.
    WRONG == classify failure -> mutate generation genome -> retry.

    The tuner is deliberately request-local. Call reset(request_id) after finalization.
    """

    _BASE_RING: Tuple[GenerationProfile, ...] = (
        GenerationProfile(strategy="direct", specialist="generalist",
                          temperature=0.20, top_p=0.90, candidate_count=1),
        GenerationProfile(strategy="decompose", specialist="planner",
                          temperature=0.30, top_p=0.92, candidate_count=2,
                          reverse_depth=1, invariant_budget=2),
        GenerationProfile(strategy="reverse", specialist="falsifier",
                          temperature=0.25, top_p=0.90, candidate_count=2,
                          reverse_depth=2, counterexample_budget=2),
        GenerationProfile(strategy="counterexample", specialist="boundary-explorer",
                          temperature=0.40, top_p=0.94, candidate_count=3,
                          reverse_depth=2, counterexample_budget=4),
        GenerationProfile(strategy="invariant", specialist="consistency-checker",
                          temperature=0.15, top_p=0.86, candidate_count=2,
                          reverse_depth=2, invariant_budget=4),
        GenerationProfile(strategy="repair", specialist="resolver",
                          temperature=0.28, top_p=0.90, candidate_count=3,
                          reverse_depth=3, counterexample_budget=3, invariant_budget=3),
    )

    def __init__(self, max_attempts: int = 6) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self._seen: Dict[str, Set[str]] = {}

    def reset(self, request_id: str) -> None:
        self._seen.pop(request_id, None)

    def initial(self, request_id: str) -> GenerationProfile:
        return self._unique(request_id, self._BASE_RING[0], attempt=0)

    def next(
        self,
        request_id: str,
        previous: GenerationProfile,
        failures: Iterable[FailureSignal],
        attempt: int,
    ) -> GenerationProfile:
        failures = list(failures)
        base = self._BASE_RING[attempt % len(self._BASE_RING)]

        # Start with a different archetype, then target the actual failure.
        p = replace(
            base,
            mutation_nonce=max(attempt, previous.mutation_nonce + 1),
            blocking_passes=3,
            queue_policy="Q_BLOCKING",
        )

        kinds = {f.kind.lower() for f in failures}

        if kinds & {"contradiction", "consistency", "logic_failure"}:
            p = replace(p, strategy="invariant", specialist="consistency-checker",
                        temperature=min(p.temperature, 0.18),
                        invariant_budget=max(p.invariant_budget, 5),
                        reverse_depth=max(p.reverse_depth, 2))

        if kinds & {"counterexample", "boundary_failure", "edge_case"}:
            p = replace(p, strategy="counterexample", specialist="boundary-explorer",
                        candidate_count=max(p.candidate_count, 3),
                        counterexample_budget=max(p.counterexample_budget, 5),
                        reverse_depth=max(p.reverse_depth, 2))

        if kinds & {"assumption_failure", "unsupported_claim", "hallucination"}:
            p = replace(p, strategy="reverse", specialist="assumption-breaker",
                        temperature=min(p.temperature, 0.22),
                        reverse_depth=max(p.reverse_depth, 3),
                        invariant_budget=max(p.invariant_budget, 3))

        if kinds & {"test_failure", "compile_failure", "runtime_failure"}:
            p = replace(p, strategy="repair", specialist="test-driven-resolver",
                        temperature=min(p.temperature, 0.20),
                        candidate_count=max(p.candidate_count, 3),
                        invariant_budget=max(p.invariant_budget, 4))

        if kinds & {"stagnation", "duplicate_answer", "no_material_improvement"}:
            p = replace(p, strategy="decompose", specialist="alternate-derivation",
                        temperature=min(0.55, max(p.temperature + 0.12, 0.32)),
                        top_p=min(0.97, max(p.top_p, 0.94)),
                        candidate_count=max(p.candidate_count, 3))

        if kinds & {"missing_information", "insufficient_information"}:
            # Do not "tune" missing facts into existence. Keep output conservative.
            p = replace(p, strategy="evidence-guard", specialist="epistemic-checker",
                        temperature=0.0, top_p=0.80, candidate_count=1,
                        counterexample_budget=max(p.counterexample_budget, 2))

        return self._unique(request_id, p, attempt=attempt)

    def _unique(self, request_id: str, profile: GenerationProfile, attempt: int) -> GenerationProfile:
        seen = self._seen.setdefault(request_id, set())
        p = profile
        nonce = max(attempt, p.mutation_nonce)

        # A retry is not allowed to reuse the same genome fingerprint.
        for _ in range(64):
            if p.fingerprint not in seen:
                seen.add(p.fingerprint)
                return p
            nonce += 1
            p = replace(
                p,
                mutation_nonce=nonce,
                # Small bounded diversity nudge so semantically identical retries do not recur.
                temperature=min(0.60, round(p.temperature + 0.01, 3)),
            )

        raise RuntimeError("RepeatTuner could not produce a unique generation profile")


def generation_id(request_id: str, attempt: int, profile: GenerationProfile) -> str:
    """Stable ID used to reject stale findings from older draft generations."""
    raw = f"{request_id}|{attempt}|{profile.fingerprint}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:24]
