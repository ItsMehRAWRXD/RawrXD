"""Architect / planner bot — Phase 41 Architect equivalent."""

from typing import List

from core.contracts import (
    LABEL_PARTIAL,
    ROLE_ARCHITECT,
    ROLE_CODE_GENERATION,
    ROLE_PLANNER,
    Bot,
    Event,
    Finding,
    make_handoff,
    make_partial,
)


class ArchitectBot(Bot):
    name = "architect-bot"
    version = "0.1.0"
    roles = {ROLE_ARCHITECT, ROLE_PLANNER}

    def supports(self, event: Event) -> bool:
        if event.kind in ("agent.goal", "goal.requested"):
            return True
        if event.kind == "role.requested":
            target = (event.payload.get("target_role") or "").lower()
            return target in self.roles or target in ("architect-bot", "planner-bot", "planner")
        return False

    async def run(self, event: Event) -> List[Finding]:
        goal = (
            event.payload.get("remaining_goal")
            or event.payload.get("goal")
            or event.payload.get("root_goal")
            or ""
        )
        goal_l = goal.lower()

        plan_steps = self._plan(goal_l)
        plan_text = " → ".join(plan_steps)

        findings: List[Finding] = [
            Finding(
                bot=self.name,
                labels={LABEL_PARTIAL},
                score=0.9,
                rationale="architect.plan",
                data={
                    "phase": "architect.plan",
                    "summary": plan_text,
                    "plan": plan_steps,
                    "artifacts": [{"type": "plan", "steps": plan_steps}],
                },
            )
        ]

        remaining = self._remaining_for_codegen(goal)
        findings.append(
            make_handoff(
                bot=self.name,
                target_role=ROLE_CODE_GENERATION,
                reason="Implementation required",
                remaining_goal=remaining,
                context={
                    "plan": plan_steps,
                    "phase": "architect.plan",
                },
                artifacts=[{"type": "plan", "steps": plan_steps}],
            )
        )
        return findings

    def _plan(self, goal_l: str) -> List[str]:
        if "compile" in goal_l or "build" in goal_l or "fix" in goal_l:
            return [
                "diagnose compile/runtime failure",
                "apply minimal code fix",
                "build and run to verify",
            ]
        if "parser" in goal_l or "parse" in goal_l:
            return [
                "specify parser interface",
                "generate parser implementation",
                "verify with sample input",
            ]
        if "test" in goal_l:
            return [
                "identify failing behavior",
                "implement fix",
                "run verification",
            ]
        return [
            "clarify goal constraints",
            "implement solution",
            "verify outcome",
        ]

    def _remaining_for_codegen(self, goal: str) -> str:
        g = goal.strip()
        if not g:
            return "Implement the requested change"
        if "verify" in g.lower() or "run" in g.lower():
            return g
        return f"Implement: {g}"
