#!/usr/bin/env python3
"""
Run HexMag as a swarm model reachable from the IDE.

Key behavior:
  * /ask returns only llm.final, never the first llm.answer candidate.
  * every request has a request_id + generation_id.
  * negative verifier/test/user feedback triggers the request-local RepeatTuner.
"""
from __future__ import annotations

import asyncio
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional, Set

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from core.contracts import Event, Finding
from run_loop import Engine


DB_FILE = "hexmag.sqlite"


class AskRequest(BaseModel):
    question: str
    code: Optional[str] = None
    timeout: float = 25.0
    max_attempts: int = 6


class AskResponse(BaseModel):
    answer: str
    sources: List[str]
    meta: Dict[str, Any]


class FeedbackRequest(BaseModel):
    request_id: str
    correct: bool
    kind: str = "wrong"
    detail: str = ""
    failed_claim: str = ""


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

    async def ask(
        self,
        question: str,
        code: Optional[str],
        timeout: float,
        max_attempts: int = 6,
    ) -> AskResponse:
        request_id = uuid.uuid4().hex

        prompt = question
        if code:
            prompt = f"{question}\n\nCode context:\n```\n{code}\n```"

        t0 = time.time()
        self.engine.add(
            Event(
                kind="llm.question",
                source_bot="API/IDE",
                payload={
                    "request_id": request_id,
                    "question": prompt,
                    "code": code,
                    "max_attempts": max_attempts,
                },
            )
        )

        sources: Set[str] = set()

        while time.time() - t0 < timeout:
            await self.engine.step()

            # Only inspect findings belonging to this request.
            for item in reversed(self.engine.history):
                data = getattr(item, "data", {})
                if data.get("request_id") != request_id:
                    continue
                labels = set(getattr(item, "labels", set()))
                if "web.content" in labels and data.get("url"):
                    sources.add(data["url"])
                if "search.results" in labels:
                    sources.update(data.get("links", []))

            final = self.engine.get_final(request_id)
            if final is not None:
                data = final.data
                state = self.engine.get_state(request_id)
                return AskResponse(
                    answer=str(data.get("answer", "")),
                    sources=sorted(sources)[:10],
                    meta={
                        "request_id": request_id,
                        "generation_id": data.get("generation_id"),
                        "status": data.get("status"),
                        "attempts": 0 if state is None else state.attempt + 1,
                        "events_processed": self.engine.event_count,
                        "findings": sum(
                            1
                            for x in self.engine.history
                            if getattr(x, "data", {}).get("request_id") == request_id
                        ),
                        "elapsed": round(time.time() - t0, 2),
                        "persistent_weight_delta_bytes": 0,
                    },
                )

            await asyncio.sleep(0.02)

        raise HTTPException(
            status_code=504,
            detail={
                "message": "Swarm did not converge before timeout",
                "request_id": request_id,
            },
        )


app = FastAPI(title="HexMag-Swarm-as-Model", version="1.1.0")
swarm = SwarmModel()


@app.post("/ask", response_model=AskResponse)
async def ask_endpoint(req: AskRequest) -> AskResponse:
    return await swarm.ask(req.question, req.code, req.timeout, req.max_attempts)


@app.post("/feedback")
async def feedback_endpoint(req: FeedbackRequest) -> Dict[str, Any]:
    """
    Feed automatic test/verifier/user judgement into the active request.

    For correct=false, HexMag immediately schedules a failure-targeted generation
    with a new generation_id/profile. It never blindly replays the same answer.
    """
    try:
        swarm.engine.submit_feedback(
            request_id=req.request_id,
            correct=req.correct,
            kind=req.kind,
            detail=req.detail,
            failed_claim=req.failed_claim,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    state = swarm.engine.get_state(req.request_id)
    return {
        "ok": True,
        "request_id": req.request_id,
        "status": None if state is None else state.status,
        "attempt": None if state is None else state.attempt,
        "generation_id": None if state is None else state.generation_id,
        "generation_profile": None if state is None else state.profile.payload(),
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    active = sum(1 for s in swarm.engine.requests.values() if s.status == "RUNNING")
    return {
        "status": "ok",
        "queue": len(swarm.engine.q),
        "active_requests": active,
        "bots": len(swarm.engine.bots),
    }


async def run(port: int = 8000) -> None:
    config = uvicorn.Config(app, host="0.0.0.0", port=port)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    asyncio.run(run(port=args.port))
