"""Model inventory + policy router for HexMag control plane.

HexMag selects WHO (role). This module selects WHICH model/backend serves that role.
Deep2 / GGUF / other backends are workers — not the orchestrator.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Mirror of src/agent/model_policy_router.hpp ModelRole
ROLE_TO_CAPABILITIES: Dict[str, Set[str]] = {
    "architect": {"chat", "plan", "reasoning"},
    "planner": {"chat", "plan", "reasoning"},
    "code_generation": {"code", "chat"},
    "debugging": {"code", "debug", "chat"},
    "verification": {"verify", "chat", "tools"},
    "review": {"chat", "review"},
    "research": {"chat", "research"},
    "summarization": {"chat", "summarize"},
    "ghost_text": {"chat", "completion"},
}


@dataclass
class ModelInfo:
    id: str
    backend: str  # deep2 | gguf | ollama | openai-compatible | swarm
    capabilities: List[str] = field(default_factory=list)
    context: int = 2048
    healthy: bool = True
    speed: str = "medium"  # fast | medium | slow
    vram_mb: int = 0
    priority: int = 100  # lower = preferred among equals

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def supports(self, caps: Set[str]) -> bool:
        have = {c.lower() for c in self.capabilities}
        return caps.issubset(have) if caps else True


@dataclass
class ModelRoute:
    role: str
    model_id: str
    backend: str
    endpoint: str = ""
    reason: str = ""
    healthy: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ModelInventory:
    """Known local models. Loaded from env / models.json / defaults."""

    def __init__(self, models: Optional[List[ModelInfo]] = None):
        self.models: List[ModelInfo] = models if models is not None else self._load()

    def _load(self) -> List[ModelInfo]:
        path = os.environ.get("HEXMAG_MODELS_JSON") or str(
            Path(__file__).resolve().parent / "models.json"
        )
        if Path(path).is_file():
            try:
                raw = json.loads(Path(path).read_text(encoding="utf-8"))
                items = raw.get("models", raw if isinstance(raw, list) else [])
                return [ModelInfo(**m) for m in items]
            except Exception as exc:
                print(f"ModelInventory: failed to load {path}: {exc}")

        # Single-model install still benefits: every role can share Deep2
        deep2_id = os.environ.get("HEXMAG_DEEP2_MODEL", "deep2:default")
        return [
            ModelInfo(
                id=deep2_id,
                backend="deep2",
                capabilities=["chat", "code", "plan", "reasoning", "debug", "verify", "review", "research", "summarize", "completion", "tools"],
                context=int(os.environ.get("HEXMAG_DEEP2_CONTEXT", "2048")),
                healthy=True,
                speed="medium",
                priority=50,
            ),
            ModelInfo(
                id="stub:deterministic",
                backend="stub",
                capabilities=["chat", "code", "plan", "verify", "tools", "debug", "review"],
                context=8192,
                healthy=True,
                speed="fast",
                priority=200,  # last resort / CI
            ),
        ]

    def list_healthy(self) -> List[ModelInfo]:
        return [m for m in self.models if m.healthy]

    def mark_unhealthy(self, model_id: str, reason: str = "") -> None:
        for m in self.models:
            if m.id == model_id:
                m.healthy = False
                print(f"ModelInventory: marked unhealthy {model_id} ({reason})")
                break

    def mark_healthy(self, model_id: str) -> None:
        for m in self.models:
            if m.id == model_id:
                m.healthy = True
                break

    def to_dict(self) -> Dict[str, Any]:
        return {"models": [m.to_dict() for m in self.models]}


class ModelPolicyRouter:
    """
    Select WHICH model serves a HexMag role.

    Routing considers: role capabilities, health, context, speed, priority.
    """

    def __init__(self, inventory: Optional[ModelInventory] = None):
        self.inventory = inventory or ModelInventory()

    def select(
        self,
        role: str,
        *,
        min_context: int = 0,
        prefer_fast: bool = False,
        model_hint: str = "",
        exclude: Optional[Set[str]] = None,
    ) -> ModelRoute:
        role_key = (role or "").strip().lower()
        needed = set(ROLE_TO_CAPABILITIES.get(role_key, {"chat"}))
        exclude = exclude or set()

        candidates = []
        for m in self.inventory.list_healthy():
            if m.id in exclude:
                continue
            if model_hint and model_hint not in (m.id, m.backend):
                # hint narrows but does not hard-fail if no match
                pass
            if min_context and m.context < min_context:
                continue
            if not m.supports(needed):
                continue
            score = m.priority
            if model_hint and (model_hint == m.id or model_hint == m.backend):
                score -= 1000
            if prefer_fast and m.speed == "fast":
                score -= 20
            if m.backend == "deep2":
                score -= 5  # prefer native when healthy and capable
            if m.backend == "stub":
                score += 50
            candidates.append((score, m))

        if not candidates:
            # Fall back to any healthy model, then stub
            healthy = self.inventory.list_healthy()
            if healthy:
                m = sorted(healthy, key=lambda x: x.priority)[0]
                return ModelRoute(
                    role=role_key,
                    model_id=m.id,
                    backend=m.backend,
                    reason="fallback: no capability-perfect match",
                    healthy=m.healthy,
                )
            return ModelRoute(
                role=role_key,
                model_id="stub:deterministic",
                backend="stub",
                reason="no healthy models in inventory",
                healthy=True,
            )

        candidates.sort(key=lambda t: t[0])
        m = candidates[0][1]
        return ModelRoute(
            role=role_key,
            model_id=m.id,
            backend=m.backend,
            reason=f"matched caps={sorted(needed)} context>={min_context}",
            healthy=m.healthy,
        )


# Process-wide defaults for bots / engine
_INVENTORY = ModelInventory()
_ROUTER = ModelPolicyRouter(_INVENTORY)


def get_inventory() -> ModelInventory:
    return _INVENTORY


def get_router() -> ModelPolicyRouter:
    return _ROUTER


def select_model_for_role(role: str, **kwargs: Any) -> ModelRoute:
    return _ROUTER.select(role, **kwargs)
