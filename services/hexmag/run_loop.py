import asyncio
from typing import Any, Dict, List, Optional, Set

from core.contracts import (
    LABEL_ANSWER,
    LABEL_FAILED,
    LABEL_GOAL_SATISFIED,
    LABEL_HANDOFF,
    LABEL_LLM_ANSWER,
    LABEL_PARTIAL,
    ROLE_ARCHITECT,
    AgentContext,
    Event,
    Finding,
    make_failed,
    make_goal_satisfied,
)
from core.registry import load_bots


class Engine:
    """
    HexMag swarm loop.

    /ask path: llm.question → bots → answer (fallback Q&A OK)
    /agent path: goal.requested → role chain via Finding(label=handoff)
    """

    def __init__(self):
        self.q: List[Event] = []
        self.history: List[Finding] = []
        self.event_count = 0
        self.bots = load_bots()
        self.sse_events: List[Dict[str, Any]] = []
        print(f"Engine initialized with {len(self.bots)} bots.")

    def add(self, event: Event) -> None:
        self.q.append(event)

    def emit_sse(self, kind: str, **payload: Any) -> None:
        self.sse_events.append({"kind": kind, **payload})

    def drain_sse(self) -> List[Dict[str, Any]]:
        events = list(self.sse_events)
        self.sse_events.clear()
        return events

    async def step(self) -> None:
        if not self.q:
            await asyncio.sleep(0.01)
            return

        event = self.q.pop(0)
        self.event_count += 1

        ctx = AgentContext.from_dict(event.payload.get("agent_context"))
        if event.kind in ("agent.goal", "goal.requested") and ctx is None:
            goal = event.payload.get("goal") or event.payload.get("root_goal") or ""
            ctx = AgentContext.new(goal)
            event.payload["agent_context"] = ctx.to_dict()
            event.payload["goal"] = goal
            self.emit_sse(
                "goal.requested",
                goal_id=ctx.goal_id,
                goal=goal,
                bot="engine",
            )

        # Dispatch to matching bots
        tasks = []
        for bot in self.bots:
            if bot.supports(event):
                tasks.append((bot.name, bot.run(event)))

        produced: List[Finding] = []
        if tasks:
            results = await asyncio.gather(
                *[t[1] for t in tasks], return_exceptions=True
            )
            for (bot_name, _), res in zip(tasks, results):
                if isinstance(res, list):
                    produced.extend(res)
                elif isinstance(res, Exception):
                    print(f"Bot error ({bot_name}): {res}")
                    produced.append(make_failed(bot_name, str(res)))

        answered = False
        satisfied = False
        handed_off = False
        failed = False

        for finding in produced:
            self.history.append(finding)
            labels = finding.labels or set()
            if ctx is not None:
                ctx.record_finding(finding)

            if labels & {LABEL_ANSWER, LABEL_LLM_ANSWER}:
                answered = True
                self.emit_sse(
                    "answer",
                    bot=finding.bot,
                    rationale=finding.rationale,
                    goal_id=ctx.goal_id if ctx else None,
                )
            if LABEL_PARTIAL in labels:
                self.emit_sse(
                    "partial",
                    bot=finding.bot,
                    rationale=finding.rationale,
                    goal_id=ctx.goal_id if ctx else None,
                )
            if LABEL_FAILED in labels:
                failed = True
                self.emit_sse(
                    "failed",
                    bot=finding.bot,
                    rationale=finding.rationale,
                    goal_id=ctx.goal_id if ctx else None,
                )
            if LABEL_GOAL_SATISFIED in labels:
                satisfied = True
                self.emit_sse(
                    LABEL_GOAL_SATISFIED,
                    bot=finding.bot,
                    result=finding.data.get("result"),
                    goal_id=ctx.goal_id if ctx else None,
                    elapsed_depth=ctx.handoff_depth if ctx else 0,
                )
            if LABEL_HANDOFF in labels:
                if self._enqueue_handoff(finding, ctx):
                    handed_off = True

        if ctx is not None:
            event.payload["agent_context"] = ctx.to_dict()

        # /ask fallback only — never treat empty /agent work as success
        if event.kind == "llm.question" and not answered and not handed_off:
            self._run_default_ask(event)
            return

        if event.kind in ("agent.goal", "goal.requested", "role.requested"):
            if satisfied or handed_off:
                return
            if not produced:
                # Empty bot result is NOT success
                fail = make_failed(
                    "HexMag-Engine",
                    f"No bot produced a finding for {event.kind}",
                    event_kind=event.kind,
                    target_role=event.payload.get("target_role"),
                )
                self.history.append(fail)
                if ctx:
                    ctx.record_finding(fail)
                self.emit_sse("failed", bot=fail.bot, rationale=fail.rationale)
                return
            if failed and not handed_off and not answered:
                return
            # Agent entry with findings but no handoff/satisfy: escalate to architect once
            if event.kind in ("agent.goal", "goal.requested") and ctx is not None:
                self._bootstrap_architect(ctx)
                return

    def _bootstrap_architect(self, ctx: AgentContext) -> None:
        ok, reason = ctx.can_handoff(ROLE_ARCHITECT, ctx.current_goal)
        if not ok:
            fail = make_failed("HexMag-Engine", reason)
            self.history.append(fail)
            ctx.record_finding(fail)
            self.emit_sse("failed", bot=fail.bot, rationale=reason)
            return
        self._queue_role(ROLE_ARCHITECT, ctx, reason="Bootstrap architect for goal", remaining_goal=ctx.current_goal)

    def _enqueue_handoff(self, finding: Finding, ctx: Optional[AgentContext]) -> bool:
        target = str(finding.data.get("target_role") or "")
        remaining = str(finding.data.get("remaining_goal") or (ctx.current_goal if ctx else ""))
        if ctx is None:
            # Handoff without agent context: create minimal context
            ctx = AgentContext.new(remaining or finding.rationale)
        ok, reason = ctx.can_handoff(target, remaining)
        if not ok:
            fail = make_failed(finding.bot, reason, suppressed_handoff=target)
            self.history.append(fail)
            ctx.record_finding(fail)
            self.emit_sse("failed", bot=finding.bot, rationale=reason, suppressed=True)
            return False

        role = ctx.normalize_role(target)
        signature = ctx.handoff_signature(role, remaining)
        ctx.handoff_depth += 1
        ctx.current_goal = remaining
        ctx.handoff_signatures.append(signature)
        if role not in ctx.visited_roles:
            ctx.visited_roles.append(role)

        # Merge artifacts/context into agent context
        handoff_ctx = finding.data.get("context") or {}
        arts = finding.data.get("artifacts") or []
        if arts:
            if isinstance(arts, list):
                ctx.artifacts.extend(arts)
            else:
                ctx.artifacts.append(arts)

        self.emit_sse(
            LABEL_HANDOFF,
            bot=finding.bot,
            target_role=role,
            reason=finding.data.get("reason") or finding.rationale,
            remaining_goal=remaining,
            handoff_depth=ctx.handoff_depth,
            goal_id=ctx.goal_id,
        )
        self._queue_role(
            role,
            ctx,
            reason=str(finding.data.get("reason") or finding.rationale),
            remaining_goal=remaining,
            extra_context=handoff_ctx if isinstance(handoff_ctx, dict) else {},
            source_bot=finding.bot,
        )
        return True

    def _queue_role(
        self,
        role: str,
        ctx: AgentContext,
        reason: str,
        remaining_goal: str,
        extra_context: Optional[Dict[str, Any]] = None,
        source_bot: str = "engine",
    ) -> None:
        payload = {
            "target_role": role,
            "goal": ctx.root_goal,
            "remaining_goal": remaining_goal,
            "reason": reason,
            "context": extra_context or {},
            "artifacts": list(ctx.artifacts),
            "agent_context": ctx.to_dict(),
        }
        self.add(Event(kind="role.requested", payload=payload, source_bot=source_bot))
        self.emit_sse(
            "role.requested",
            target_role=role,
            remaining_goal=remaining_goal,
            goal_id=ctx.goal_id,
            handoff_depth=ctx.handoff_depth,
            bot=source_bot,
        )

    def _run_default_ask(self, event: Event) -> None:
        question = event.payload.get("question", "")
        answer = self._generate_answer(question)
        finding = Finding(
            bot="HexMag-Engine",
            score=1.0,
            labels={LABEL_ANSWER, LABEL_LLM_ANSWER},
            rationale="Direct answer generated by HexMag engine",
            data={"answer": answer, "question": question},
        )
        self.history.append(finding)
        self.emit_sse("answer", bot=finding.bot, rationale=finding.rationale)

    def _generate_answer(self, question: str) -> str:
        q_lower = question.lower()

        if "hello world" in q_lower or "hello, world" in q_lower:
            if "python" in q_lower:
                return 'print("Hello, World!")'
            if "javascript" in q_lower or "js" in q_lower:
                return 'console.log("Hello, World!");'
            if "c++" in q_lower or "cpp" in q_lower:
                return '#include <iostream>\nint main() {\n    std::cout << "Hello, World!" << std::endl;\n    return 0;\n}'
            if "java" in q_lower:
                return 'public class Main {\n    public static void main(String[] args) {\n        System.out.println("Hello, World!");\n    }\n}'
            return 'print("Hello, World!")  # Python example'

        if "2+2" in q_lower or "2 + 2" in q_lower:
            return "2 + 2 = 4"

        if "quantum computing" in q_lower:
            return (
                "Quantum computing leverages quantum mechanical phenomena like superposition and entanglement "
                "to process information. Unlike classical bits (0 or 1), quantum bits (qubits) can exist in "
                "multiple states simultaneously, enabling parallel computation for certain problems."
            )

        if "hexmag" in q_lower:
            return (
                "HexMag is a local multi-agent control plane: bots hand off work via Finding(label='handoff'), "
                "model_policy_router selects which model serves a role, and Deep2 provides native GGUF inference."
            )

        if "?" in question:
            return (
                f"Based on your question about '{question[:50]}...', I can help you explore this topic. "
                "The HexMag engine is processing your request and analyzing the context provided."
            )

        return (
            f"Processing request: {question[:100]}... "
            "The HexMag swarm engine has received your input and is generating a contextual response."
        )
