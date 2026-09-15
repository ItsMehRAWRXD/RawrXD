#!/usr/bin/env python3
"""
HexMag control plane — IDE submits intent here; HexMag decides WHO, then WHAT model.

$ python hexmag_engine.py --port 8001
"""
import argparse
import asyncio
import json
import sqlite3
import time
from typing import Any, AsyncIterator, Dict, List, Optional, Set

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

try:
    from core.contracts import (
        LABEL_ANSWER,
        LABEL_GOAL_SATISFIED,
        LABEL_LLM_ANSWER,
        Event,
        Finding,
    )
    from core.model_policy_router import get_inventory, select_model_for_role
    from run_loop import Engine
except ImportError:
    print("Warning: HexMag core files not found. Using stubs.")
    from core.contracts import Event, Finding  # type: ignore
    from run_loop import Engine  # type: ignore

    def get_inventory():  # type: ignore
        class _I:
            def to_dict(self):
                return {"models": []}

        return _I()

    def select_model_for_role(role, **kwargs):  # type: ignore
        class _R:
            def to_dict(self):
                return {"role": role, "model_id": "stub", "backend": "stub"}

        return _R()


DB_FILE = "hexmag.sqlite"


class AskRequest(BaseModel):
    question: str
    code: Optional[str] = None
    timeout: float = 25.0


class AskResponse(BaseModel):
    answer: str
    sources: List[str]
    meta: Dict[str, Any]


class AgentRequest(BaseModel):
    goal: str
    max_time: float = 30.0


class SwarmModel:
    def __init__(self) -> None:
        self.engine = Engine()
        self.db_init()

    def db_init(self) -> None:
        with sqlite3.connect(DB_FILE) as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    ts REAL,
                    bot TEXT,
                    score REAL,
                    labels TEXT,
                    rationale TEXT,
                    data TEXT
                )
                """
            )

    async def ask(self, question: str, code: Optional[str], timeout: float) -> AskResponse:
        prompt = question
        if code:
            prompt = f"{question}\n\nCode context:\n```\n{code}\n```"

        t0 = time.time()
        hist_before = len(self.engine.history)
        self.engine.add(
            Event(kind="llm.question", payload={"question": prompt}, source_bot="API/IDE")
        )

        sources: Set[str] = set()
        while time.time() - t0 < timeout:
            await self.engine.step()
            self.engine.drain_sse()

            final_answer: Optional[Finding] = None
            for item in reversed(self.engine.history[hist_before:]):
                labels = getattr(item, "labels", set()) or set()
                data = getattr(item, "data", {}) or {}
                if "web.content" in labels and data.get("url"):
                    sources.add(data["url"])
                if "search.results" in labels:
                    sources.update(data.get("links", []))
                if final_answer is None and (labels & {LABEL_ANSWER, LABEL_LLM_ANSWER, "llm.answer"}):
                    final_answer = item

            if final_answer:
                return AskResponse(
                    answer=final_answer.data.get("answer", ""),
                    sources=sorted(sources)[:10],
                    meta={
                        "events_processed": self.engine.event_count,
                        "findings": len(self.engine.history) - hist_before,
                        "elapsed": round(time.time() - t0, 2),
                    },
                )
            await asyncio.sleep(0.05)

        raise HTTPException(status_code=504, detail="Swarm did not produce an answer in time")

    async def agent_stream(self, goal: str, max_time: float) -> AsyncIterator[Dict[str, Any]]:
        """Drive goal.requested → handoffs → goal.satisfied, yielding SSE payloads."""
        t0 = time.time()
        hist_before = len(self.engine.history)
        self.engine.drain_sse()
        self.engine.add(
            Event(
                kind="goal.requested",
                payload={"goal": goal, "root_goal": goal},
                source_bot="API/IDE",
            )
        )

        while time.time() - t0 < max_time:
            await self.engine.step()
            for evt in self.engine.drain_sse():
                evt.setdefault("elapsed", round(time.time() - t0, 2))
                yield evt
                if evt.get("kind") == LABEL_GOAL_SATISFIED:
                    return
                if evt.get("kind") == "failed" and evt.get("suppressed"):
                    continue

            # Terminal check on findings if SSE missed
            for item in reversed(self.engine.history[hist_before:]):
                labels = getattr(item, "labels", set()) or set()
                if LABEL_GOAL_SATISFIED in labels:
                    yield {
                        "kind": LABEL_GOAL_SATISFIED,
                        "bot": item.bot,
                        "result": (item.data or {}).get("result"),
                        "elapsed": round(time.time() - t0, 2),
                    }
                    return

            if not self.engine.q:
                # Idle with no satisfaction → allow a few more drains then fail
                await asyncio.sleep(0.05)
                if not self.engine.q:
                    # One more step in case of race
                    await self.engine.step()
                    for evt in self.engine.drain_sse():
                        evt.setdefault("elapsed", round(time.time() - t0, 2))
                        yield evt
                        if evt.get("kind") == LABEL_GOAL_SATISFIED:
                            return
                    if not any(
                        LABEL_GOAL_SATISFIED in (f.labels or set())
                        for f in self.engine.history[hist_before:]
                    ):
                        yield {
                            "kind": "failed",
                            "detail": "Agent idle without goal.satisfied",
                            "elapsed": round(time.time() - t0, 2),
                        }
                        return
            else:
                await asyncio.sleep(0.02)

        yield {"kind": "error", "detail": "Goal execution timeout", "elapsed": round(time.time() - t0, 2)}


app = FastAPI(title="HexMag-Swarm-Control-Plane", version="1.1.0")
swarm = SwarmModel()


@app.post("/ask", response_model=AskResponse)
async def ask_endpoint(req: AskRequest) -> AskResponse:
    return await swarm.ask(req.question, req.code, req.timeout)


@app.post("/agent")
async def agent_endpoint(req: AgentRequest):
    async def event_generator():
        async for evt in swarm.agent_stream(req.goal, req.max_time):
            yield f"data: {json.dumps(evt)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "queue": len(getattr(swarm.engine, "q", [])),
        "bots": [b.name for b in getattr(swarm.engine, "bots", [])],
    }


@app.get("/models")
def models() -> Dict[str, Any]:
    """Model inventory for role→backend routing (Deep2 is a worker, not the boss)."""
    return get_inventory().to_dict()


@app.get("/route/{role}")
def route_role(role: str) -> Dict[str, Any]:
    return select_model_for_role(role).to_dict()


async def run(port: int = 8000) -> None:
    # Single stepper: avoid racing a background pump against /agent
    config = uvicorn.Config(app, host="0.0.0.0", port=port)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    args = parser.parse_args()
    asyncio.run(run(port=args.port))
