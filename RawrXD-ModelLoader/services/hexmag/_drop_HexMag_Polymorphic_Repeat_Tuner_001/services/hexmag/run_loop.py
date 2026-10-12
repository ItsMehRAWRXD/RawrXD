from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from core.contracts import Event, Finding
from core.registry import load_bots
from core.repeat_tuner import FailureSignal, GenerationProfile, RepeatTuner, generation_id


FAILURE_LABELS = {
    "verification.failed",
    "wrong",
    "failed",
    "contradiction",
    "counterexample",
    "assumption_failure",
    "invariant_failure",
    "unsupported_claim",
    "hallucination",
    "test_failure",
    "compile_failure",
    "runtime_failure",
}

PASS_LABELS = {
    "verification.pass",
    "verification.survived",
    "goal.satisfied",
}


@dataclass
class RequestState:
    request_id: str
    question: str
    attempt: int
    profile: GenerationProfile
    generation_id: str
    max_attempts: int
    code: Optional[str] = None

    candidate: Optional[Finding] = None
    final: Optional[Finding] = None
    failures: List[FailureSignal] = field(default_factory=list)
    answer_history: List[str] = field(default_factory=list)
    status: str = "RUNNING"


class Engine:
    """
    HexMag event loop with request-local polymorphic retries.

    Invariants:
      * first answer is a candidate, not a final answer;
      * a verifier/test/reverse failure triggers a tuned new generation;
      * retries may not reuse the same generation profile;
      * stale generation findings are discarded;
      * retries use Q_BLOCKING with 3 cyclic passes;
      * tuning changes request-local structure/policy, never persistent weights.
    """

    def __init__(self, max_attempts: int = 6):
        self.q: List[Event] = []
        self.history: List[Finding] = []
        self.event_count = 0
        self.bots = load_bots()
        self.tuner = RepeatTuner(max_attempts=max_attempts)
        self.max_attempts = max_attempts
        self.requests: Dict[str, RequestState] = {}
        print(f"Engine initialized with {len(self.bots)} bots.")

    def add(self, event: Event) -> None:
        if event.kind == "llm.question":
            self._ensure_request(event)
        self.q.append(event)

    def _ensure_request(self, event: Event) -> RequestState:
        request_id = str(event.payload.get("request_id", "")).strip()
        if not request_id:
            raise ValueError("HexMag llm.question requires payload.request_id")

        state = self.requests.get(request_id)
        if state is not None:
            return state

        profile = self.tuner.initial(request_id)
        gid = generation_id(request_id, 0, profile)
        state = RequestState(
            request_id=request_id,
            question=str(event.payload.get("question", "")),
            code=event.payload.get("code"),
            attempt=0,
            profile=profile,
            generation_id=gid,
            max_attempts=int(event.payload.get("max_attempts", self.max_attempts)),
        )
        self.requests[request_id] = state
        return state

    def get_final(self, request_id: str) -> Optional[Finding]:
        state = self.requests.get(request_id)
        return None if state is None else state.final

    def get_state(self, request_id: str) -> Optional[RequestState]:
        return self.requests.get(request_id)

    def submit_feedback(
        self,
        request_id: str,
        correct: bool,
        kind: str = "wrong",
        detail: str = "",
        failed_claim: str = "",
    ) -> None:
        """
        Feed an automatic test/verifier/user feedback result back into the loop.

        A negative verdict never replays the same generation. It produces a new,
        failure-targeted generation profile.
        """
        state = self.requests.get(request_id)
        if state is None:
            raise KeyError(f"unknown request_id: {request_id}")

        if correct:
            if state.candidate is not None and state.final is None:
                self._finalize(state, state.candidate, verified_by="external-feedback")
            return

        failure = FailureSignal(kind=kind, detail=detail, failed_claim=failed_claim)
        self._schedule_retry(state, [failure])

    async def step(self) -> None:
        if not self.q:
            await asyncio.sleep(0.01)
            return

        event = self.q.pop(0)
        self.event_count += 1

        request_id = str(event.payload.get("request_id", "")).strip()
        state = self.requests.get(request_id) if request_id else None

        # Ignore stale events after a retry changed generation_id.
        if state is not None:
            event_gid = str(event.payload.get("generation_id", state.generation_id))
            if event_gid != state.generation_id:
                return
            if state.status in {"CONVERGED", "PROVEN", "INSUFFICIENT_INFORMATION", "FAILED"}:
                return

        handled, findings = await self._dispatch(event)

        if state is not None:
            findings = [self._stamp_finding(f, state) for f in findings]
            findings = [f for f in findings if self._finding_is_current(f, state)]

        if findings:
            self.history.extend(findings)

        # Failure signals have priority over candidate acceptance.
        failures = self._collect_failures(findings)
        if state is not None and failures:
            self._schedule_retry(state, failures)
            return

        if event.kind == "response.verify" and state is not None:
            # If a verifier handled the event and produced no explicit failure,
            # accept only an explicit pass. If no verifier exists, use the
            # built-in sanity/reverse-availability gate below.
            if handled:
                if any(PASS_LABELS & set(f.labels) for f in findings):
                    if state.candidate is not None:
                        self._finalize(state, state.candidate, verified_by="swarm-verifier")
                else:
                    self._schedule_retry(
                        state,
                        [FailureSignal("verification_failed", "Verifier produced no pass signal")],
                    )
            elif state.candidate is not None:
                # No specialized verifier loaded: candidate may survive only the
                # deterministic checks. This is convergence, not proof.
                self._finalize(state, state.candidate, verified_by="available-checks")
            return

        if state is not None:
            candidates = [f for f in findings if "llm.answer" in set(f.labels)]
            if candidates:
                candidate = max(candidates, key=lambda f: float(f.score))
                failure = self._builtin_candidate_check(state, candidate)
                if failure is not None:
                    self._schedule_retry(state, [failure])
                    return

                state.candidate = candidate
                answer = str(candidate.data.get("answer", ""))
                state.answer_history.append(answer)

                self.q.append(
                    Event(
                        kind="response.verify",
                        source_bot="HexMag-Engine",
                        payload={
                            "request_id": state.request_id,
                            "generation_id": state.generation_id,
                            "attempt": state.attempt,
                            "question": state.question,
                            "code": state.code,
                            "candidate": answer,
                            "generation_profile": state.profile.payload(),
                            "verification_contract": {
                                "check_contradictions": True,
                                "check_counterexamples": True,
                                "check_invariants": True,
                                "check_reverse_consistency": True,
                                "reject_unsupported_claims": True,
                            },
                        },
                    )
                )
                return

        if event.kind == "llm.question" and state is not None and not handled:
            self._run_default_logic(event, state)

    async def _dispatch(self, event: Event) -> Tuple[bool, List[Finding]]:
        tasks = []
        for bot in self.bots:
            try:
                if bot.supports(event):
                    tasks.append(bot.run(event))
            except Exception as exc:
                self.history.append(
                    Finding(
                        bot=getattr(bot, "name", "unknown-bot"),
                        labels={"bot.error"},
                        score=0.0,
                        rationale=str(exc),
                        data={"event_kind": event.kind},
                    )
                )

        if not tasks:
            return False, []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: List[Finding] = []
        for res in results:
            if isinstance(res, list):
                findings.extend(x for x in res if isinstance(x, Finding))
            elif isinstance(res, Exception):
                self.history.append(
                    Finding(
                        bot="HexMag-Engine",
                        labels={"bot.error"},
                        score=0.0,
                        rationale=str(res),
                        data={"event_kind": event.kind},
                    )
                )
        return True, findings

    def _stamp_finding(self, finding: Finding, state: RequestState) -> Finding:
        finding.data.setdefault("request_id", state.request_id)
        finding.data.setdefault("generation_id", state.generation_id)
        finding.data.setdefault("attempt", state.attempt)
        finding.data.setdefault("generation_profile", state.profile.payload())
        return finding

    def _finding_is_current(self, finding: Finding, state: RequestState) -> bool:
        return str(finding.data.get("generation_id", "")) == state.generation_id

    def _collect_failures(self, findings: Sequence[Finding]) -> List[FailureSignal]:
        out: List[FailureSignal] = []
        for f in findings:
            labels = set(f.labels)
            hit = FAILURE_LABELS & labels
            if not hit:
                continue
            kind = sorted(hit)[0]
            out.append(
                FailureSignal(
                    kind=kind,
                    detail=str(f.data.get("detail", f.rationale)),
                    failed_claim=str(f.data.get("failed_claim", "")),
                    severity=max(0.0, min(1.0, 1.0 - float(f.score))),
                )
            )
        return out

    def _builtin_candidate_check(self, state: RequestState, finding: Finding) -> Optional[FailureSignal]:
        answer = str(finding.data.get("answer", "")).strip()
        if not answer:
            return FailureSignal("empty_answer", "Candidate answer was empty")

        placeholder_fragments = (
            "the hexmag engine is processing your request",
            "received your input and is generating",
            "i can help you explore this topic",
            "processing request:",
        )
        lowered = answer.lower()
        if any(fragment in lowered for fragment in placeholder_fragments):
            return FailureSignal("unsupported_claim", "Placeholder/meta answer is not task completion")

        if float(finding.score) < 0.50:
            return FailureSignal("low_verifier_score", f"candidate score={finding.score}")

        if state.answer_history and answer == state.answer_history[-1]:
            return FailureSignal("duplicate_answer", "Retry reproduced the same answer")

        if finding.data.get("tests_passed") is False:
            return FailureSignal("test_failure", str(finding.data.get("test_output", "tests failed")))
        if finding.data.get("compile_ok") is False:
            return FailureSignal("compile_failure", str(finding.data.get("compile_output", "compile failed")))
        if finding.data.get("runtime_ok") is False:
            return FailureSignal("runtime_failure", str(finding.data.get("runtime_output", "runtime failed")))

        return None

    def _schedule_retry(self, state: RequestState, failures: Sequence[FailureSignal]) -> None:
        if state.status != "RUNNING":
            return

        state.failures.extend(failures)

        if state.attempt + 1 >= state.max_attempts:
            self._finalize_insufficient(state, failures)
            return

        state.attempt += 1
        state.profile = self.tuner.next(
            request_id=state.request_id,
            previous=state.profile,
            failures=failures,
            attempt=state.attempt,
        )
        state.generation_id = generation_id(state.request_id, state.attempt, state.profile)
        state.candidate = None

        self.q.append(
            Event(
                kind="llm.question",
                source_bot="HexMag-RepeatTuner",
                payload={
                    "request_id": state.request_id,
                    "generation_id": state.generation_id,
                    "attempt": state.attempt,
                    "question": state.question,
                    "code": state.code,
                    "retry": True,
                    "queue_policy": "Q_BLOCKING",
                    "blocking_passes": 3,
                    "generation_profile": state.profile.payload(),
                    "failure_context": [
                        {
                            "kind": f.kind,
                            "detail": f.detail,
                            "failed_claim": f.failed_claim,
                            "severity": f.severity,
                            "fingerprint": f.fingerprint,
                        }
                        for f in failures
                    ],
                    "instruction": (
                        "Do not repeat the previous answer. Repair the specific failure_context. "
                        "Use the generation_profile strategy and produce a materially different candidate."
                    ),
                },
            )
        )

    def _finalize(self, state: RequestState, candidate: Finding, verified_by: str) -> None:
        answer = str(candidate.data.get("answer", "")).strip()
        state.status = "CONVERGED"
        state.final = Finding(
            bot="HexMag-Resolver",
            labels={"llm.final", "goal.satisfied", "converged"},
            score=float(candidate.score),
            rationale=f"Candidate survived {verified_by}",
            data={
                "request_id": state.request_id,
                "generation_id": state.generation_id,
                "attempt": state.attempt,
                "answer": answer,
                "status": "CONVERGED",
                "verified_by": verified_by,
                "generation_profile": state.profile.payload(),
                "persistent_weight_delta_bytes": 0,
            },
        )
        self.history.append(state.final)
        self.tuner.reset(state.request_id)

    def _finalize_insufficient(self, state: RequestState, failures: Sequence[FailureSignal]) -> None:
        state.status = "INSUFFICIENT_INFORMATION"
        state.final = Finding(
            bot="HexMag-Resolver",
            labels={"llm.final", "insufficient_information"},
            score=0.0,
            rationale="Retry budget exhausted without a verified candidate",
            data={
                "request_id": state.request_id,
                "generation_id": state.generation_id,
                "attempt": state.attempt,
                "answer": "INSUFFICIENT_INFORMATION",
                "status": "INSUFFICIENT_INFORMATION",
                "failures": [
                    {"kind": f.kind, "detail": f.detail, "failed_claim": f.failed_claim}
                    for f in failures
                ],
                "persistent_weight_delta_bytes": 0,
            },
        )
        self.history.append(state.final)
        self.tuner.reset(state.request_id)

    def _run_default_logic(self, event: Event, state: RequestState) -> None:
        """
        Small deterministic fallback for smoke testing only.

        Placeholder prose is intentionally rejected by _builtin_candidate_check,
        so this fallback cannot fake task completion for unknown questions.
        """
        question = str(event.payload.get("question", ""))
        q_lower = question.lower()

        if "2+2" in q_lower or "2 + 2" in q_lower:
            answer = "2 + 2 = 4"
        elif "hello world" in q_lower or "hello, world" in q_lower:
            if "c++" in q_lower or "cpp" in q_lower:
                answer = '#include <iostream>\nint main(){std::cout<<"Hello, World!\\n";}'
            else:
                answer = 'print("Hello, World!")'
        else:
            answer = f"Processing request: {question[:100]}..."

        finding = Finding(
            bot="HexMag-Engine",
            labels={"llm.answer"},
            score=1.0,
            rationale="Deterministic fallback candidate",
            data={
                "answer": answer,
                "request_id": state.request_id,
                "generation_id": state.generation_id,
                "attempt": state.attempt,
            },
        )
        self.history.append(finding)

        failure = self._builtin_candidate_check(state, finding)
        if failure is not None:
            self._schedule_retry(state, [failure])
        else:
            state.candidate = finding
            state.answer_history.append(answer)
            self.q.append(
                Event(
                    kind="response.verify",
                    source_bot="HexMag-Engine",
                    payload={
                        "request_id": state.request_id,
                        "generation_id": state.generation_id,
                        "attempt": state.attempt,
                        "question": state.question,
                        "candidate": answer,
                        "generation_profile": state.profile.payload(),
                    },
                )
            )
