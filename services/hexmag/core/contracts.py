from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Set, Optional
import uuid


# Canonical finding labels (first-class HexMag results)
LABEL_ANSWER = "answer"
LABEL_PARTIAL = "partial"
LABEL_HANDOFF = "handoff"
LABEL_GOAL_SATISFIED = "goal.satisfied"
LABEL_FAILED = "failed"

# Back-compat aliases used by /ask and older bots
LABEL_LLM_ANSWER = "llm.answer"

# Role names (WHO works next) — map to model_policy_router roles externally
ROLE_ARCHITECT = "architect"
ROLE_PLANNER = "planner"
ROLE_CODE_GENERATION = "code_generation"
ROLE_VERIFICATION = "verification"
ROLE_REVIEW = "review"

ROLE_ALIASES = {
    "architect-bot": ROLE_ARCHITECT,
    "planner-bot": ROLE_PLANNER,
    "planner": ROLE_PLANNER,
    "codegen": ROLE_CODE_GENERATION,
    "codegen-bot": ROLE_CODE_GENERATION,
    "coder": ROLE_CODE_GENERATION,
    "verification-bot": ROLE_VERIFICATION,
    "verifier": ROLE_VERIFICATION,
    "qa": ROLE_VERIFICATION,
    "reviewer": ROLE_REVIEW,
}

DEFAULT_MAX_HANDOFF_DEPTH = 8


@dataclass(frozen=True)
class Event:
    """Drive message flowing through the swarm."""

    kind: str
    payload: Dict[str, Any]
    source_bot: str = "user/initial"


@dataclass
class Finding:
    """Structured result produced by a bot."""

    bot: str
    labels: Set[str]
    score: float
    rationale: str
    data: Dict[str, Any] = field(default_factory=dict)

    def has(self, label: str) -> bool:
        return label in (self.labels or set())


@dataclass
class AgentContext:
    """Shared orchestration state carried across handoffs."""

    goal_id: str
    root_goal: str
    current_goal: str
    handoff_depth: int = 0
    visited_roles: List[str] = field(default_factory=list)
    # Successful handoff signatures only (role|remaining_goal). Checked before enqueue.
    handoff_signatures: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Any] = field(default_factory=list)
    tool_results: List[Any] = field(default_factory=list)
    max_handoff_depth: int = DEFAULT_MAX_HANDOFF_DEPTH

    @classmethod
    def new(cls, goal: str, max_handoff_depth: int = DEFAULT_MAX_HANDOFF_DEPTH) -> "AgentContext":
        return cls(
            goal_id=str(uuid.uuid4()),
            root_goal=goal,
            current_goal=goal,
            max_handoff_depth=max_handoff_depth,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional["AgentContext"]:
        if not data:
            return None
        return cls(
            goal_id=str(data.get("goal_id") or uuid.uuid4()),
            root_goal=str(data.get("root_goal") or ""),
            current_goal=str(data.get("current_goal") or data.get("root_goal") or ""),
            handoff_depth=int(data.get("handoff_depth") or 0),
            visited_roles=list(data.get("visited_roles") or []),
            handoff_signatures=list(data.get("handoff_signatures") or []),
            findings=list(data.get("findings") or []),
            artifacts=list(data.get("artifacts") or []),
            tool_results=list(data.get("tool_results") or []),
            max_handoff_depth=int(data.get("max_handoff_depth") or DEFAULT_MAX_HANDOFF_DEPTH),
        )

    def normalize_role(self, role: str) -> str:
        key = (role or "").strip().lower()
        return ROLE_ALIASES.get(key, key)

    def handoff_signature(self, target_role: str, remaining_goal: str) -> str:
        role = self.normalize_role(target_role)
        return f"{role}|{(remaining_goal or '').strip().lower()}"

    def can_handoff(self, target_role: str, remaining_goal: str) -> tuple[bool, str]:
        role = self.normalize_role(target_role)
        if self.handoff_depth >= self.max_handoff_depth:
            return False, f"max handoff depth {self.max_handoff_depth} reached"
        signature = self.handoff_signature(role, remaining_goal)
        # Only signatures from *successful* prior enqueues suppress repeats
        if signature in self.handoff_signatures:
            return False, f"repeated handoff suppressed for role={role}"
        return True, ""

    def record_finding(self, finding: Finding) -> None:
        primary = next(iter(finding.labels), "unknown") if finding.labels else "unknown"
        entry = {
            "bot": finding.bot,
            "label": primary,
            "labels": sorted(finding.labels or []),
            "rationale": finding.rationale,
            "target_role": finding.data.get("target_role"),
            "remaining_goal": finding.data.get("remaining_goal"),
        }
        self.findings.append(entry)
        arts = finding.data.get("artifacts")
        if arts:
            if isinstance(arts, list):
                self.artifacts.extend(arts)
            else:
                self.artifacts.append(arts)


class Bot:
    """Abstract base class for all swarm bots."""

    name: str = "base-bot"
    version: str = "0.0.1"
    # Role(s) this bot serves when receiving role.requested events
    roles: Set[str] = set()

    def supports(self, event: Event) -> bool:
        raise NotImplementedError

    async def run(self, event: Event) -> List[Finding]:
        raise NotImplementedError

    def supports_role(self, role: str) -> bool:
        aliases = ROLE_ALIASES
        normalized = aliases.get((role or "").strip().lower(), (role or "").strip().lower())
        return normalized in {aliases.get(r, r) for r in (self.roles or set())} or normalized in (self.roles or set())


def make_handoff(
    bot: str,
    target_role: str,
    reason: str,
    remaining_goal: str,
    context: Optional[Dict[str, Any]] = None,
    artifacts: Optional[List[Any]] = None,
    score: float = 1.0,
) -> Finding:
    return Finding(
        bot=bot,
        labels={LABEL_HANDOFF},
        score=score,
        rationale=reason,
        data={
            "target_role": target_role,
            "reason": reason,
            "context": context or {},
            "artifacts": artifacts or [],
            "remaining_goal": remaining_goal,
        },
    )


def make_answer(bot: str, answer: str, rationale: str = "", **extra: Any) -> Finding:
    data = {"answer": answer, **extra}
    return Finding(
        bot=bot,
        labels={LABEL_ANSWER, LABEL_LLM_ANSWER},
        score=1.0,
        rationale=rationale or "Answer produced",
        data=data,
    )


def make_partial(bot: str, summary: str, **extra: Any) -> Finding:
    return Finding(
        bot=bot,
        labels={LABEL_PARTIAL},
        score=0.7,
        rationale=summary,
        data={"summary": summary, **extra},
    )


def make_failed(bot: str, reason: str, **extra: Any) -> Finding:
    return Finding(
        bot=bot,
        labels={LABEL_FAILED},
        score=0.0,
        rationale=reason,
        data={"reason": reason, **extra},
    )


def make_goal_satisfied(bot: str, result: str, **extra: Any) -> Finding:
    return Finding(
        bot=bot,
        labels={LABEL_GOAL_SATISFIED},
        score=1.0,
        rationale="Goal satisfied",
        data={"result": result, **extra},
    )
