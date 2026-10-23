#!/usr/bin/env python3
"""
Deep2 Local OpenAI-compatible server on port 11436.

Wraps the existing rawr.exe CLI (one-shot generator) to expose the
OpenAI-compatible endpoints Copilot's "Deep2 Local" custom endpoint expects:

  GET  /health
  GET  /v1/models
  POST /v1/chat/completions   (supports stream=false and stream=true)

This is a thin adapter service. It does NOT rebuild or modify rawr.exe or the
Deep2 engine binary.
"""
import asyncio
import contextlib
import json
import os
import subprocess
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict

RAWR_EXE = os.environ.get(
    "DEEP2_RAWR_EXE", r"G:\VSC0de\Deep2Engine\build-cli\bin\Release\rawr.exe"
)
DEFAULT_MODEL = "llama3.2:3b"

# Seconds allowed for a single rawr.exe inference call (model load + generate).
# Model loading + Vulkan init can take 90-120s on first launch, so this must be
# generous enough to avoid killing in-flight requests.
INFERENCE_TIMEOUT = int(os.environ.get("DEEP2_INFERENCE_TIMEOUT", "600"))

# Serialize inference: only one rawr.exe at a time to avoid GPU/Vulkan
# contention from multiple concurrent model loads.
inference_lock = asyncio.Lock()

@dataclass
class OwnedProcess:
    request_id: str
    process: asyncio.subprocess.Process
    job_handle: Any = None
    started_at: float = 0.0


_active_processes: Dict[str, OwnedProcess] = {}
_active_processes_lock = asyncio.Lock()
_process_events: List[Dict[str, Any]] = []
_process_events_lock = asyncio.Lock()


async def _record_process_event(event: str, entry: OwnedProcess, **extra: Any) -> None:
    record = {
        "event": event, "request_id": entry.request_id, "pid": entry.process.pid,
        "started_at": entry.started_at, "elapsed_ms": round((time.monotonic() - entry.started_at) * 1000, 1),
        **extra,
    }
    async with _process_events_lock:
        _process_events.append(record)
        del _process_events[:-256]


class InferenceCancelled(Exception):
    """The caller disconnected or the request task was cancelled."""


def _create_windows_job(pid: int) -> Any:
    """Create a kill-on-close Job Object and assign only *pid* to it."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                        ("WriteOperationCount", ctypes.c_ulonglong),
                        ("OtherOperationCount", ctypes.c_ulonglong),
                        ("ReadTransferCount", ctypes.c_ulonglong),
                        ("WriteTransferCount", ctypes.c_ulonglong),
                        ("OtherTransferCount", ctypes.c_ulonglong)]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BasicLimit),
                        ("IoInfo", IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = ExtendedLimit()
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
        info.BasicLimitInformation.LimitFlags = 0x2000
        kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT,
                                                       ctypes.c_void_p, wintypes.DWORD]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            kernel32.CloseHandle(handle)
            return None
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        process_handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
        if not process_handle or not kernel32.AssignProcessToJobObject(handle, process_handle):
            if process_handle:
                kernel32.CloseHandle(process_handle)
            kernel32.CloseHandle(handle)
            return None
        kernel32.CloseHandle(process_handle)
        return handle
    except Exception:  # noqa: BLE001
        return None


def _close_windows_job(handle: Any) -> None:
    if not handle or os.name != "nt":
        return
    try:
        import ctypes
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
    except Exception:  # noqa: BLE001
        pass


async def _terminate_owned(entry: OwnedProcess) -> None:
    """Terminate only the process tree owned by this request."""
    proc = entry.process
    try:
        if entry.job_handle and os.name == "nt":
            import ctypes
            ctypes.WinDLL("kernel32", use_last_error=True).TerminateJobObject(entry.job_handle, 1)
        elif proc.returncode is None:
            if os.name == "nt":
                proc.terminate()
            else:
                import signal
                os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception:  # noqa: BLE001
        with contextlib.suppress(Exception):
            proc.kill()
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=2)
    finally:
        _close_windows_job(entry.job_handle)


async def _terminate_all_owned() -> None:
    async with _active_processes_lock:
        entries = list(_active_processes.values())
        _active_processes.clear()
    await asyncio.gather(*(_terminate_owned(e) for e in entries), return_exceptions=True)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    yield
    await _terminate_all_owned()

# Client-facing model identifiers -> rawr.exe-resolvable model names.
MODEL_ALIASES = {
    "deep2-local": DEFAULT_MODEL,
    "Deep2 Local": DEFAULT_MODEL,
}

SUPPORTED_MODELS = {DEFAULT_MODEL, "qwen3:8b"}


def resolve_model(requested_model: Optional[str]) -> str:
    """Map a client-facing model id to a rawr.exe-resolvable model name."""
    requested_model = requested_model or DEFAULT_MODEL
    resolved = MODEL_ALIASES.get(requested_model, requested_model)
    if resolved not in SUPPORTED_MODELS:
        raise ValueError(f"Unsupported model: {requested_model}")
    return resolved

app = FastAPI(title="Deep2 Local OpenAI-Compatible Server", version="1.0.0", lifespan=_lifespan)


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    role: str
    content: str


class ChatCompletionsRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: Optional[str] = DEFAULT_MODEL
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.2
    max_tokens: Optional[int] = 128
    stream: Optional[bool] = False
    top_p: Optional[float] = None
    top_k: Optional[int] = None
    n: Optional[int] = None


class ModelInfo(BaseModel):
    id: str
    object: str = "model"
    created: int
    owned_by: str = "deep2-local"


_DIAG_PREFIXES = (
    "[",
    "[ROM",
    "[ADMISSION",
    "[VULKAN",
    "[ROPE_ADAPT",
    "[Llama]",
    "[KV_WINDOW]",
    "rawr.exe",
    "Loaded",
    "shard",
    "index complete",
    "admitted",
    "found GPU",
    "skipping",
    "initialized",
    "ready",
    "forward pass",
    "advertised",
)


def _extract_generation_text(raw_output: str) -> str:
    """Strip rawr.exe diagnostic lines, keeping only the generated response."""
    content_lines: List[str] = []
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in _DIAG_PREFIXES):
            continue
        content_lines.append(stripped)
    content = "\n".join(content_lines).strip()
    return content or raw_output.strip()


def _build_response(model: str, content: str) -> Dict[str, Any]:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
    }


def _build_chunk(model: str, delta: Dict[str, str], finish_reason: Any) -> Dict[str, Any]:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {"index": 0, "delta": delta, "finish_reason": finish_reason}
        ],
    }


async def _run_owned_inference(
    request: Request, request_id: str, model: str, prompt: str,
    max_tokens: int, temperature: float,
) -> str:
    """Run one owned rawr.exe process and reap it on every exit path."""
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    kwargs: Dict[str, Any] = {"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE}
    if creationflags:
        kwargs["creationflags"] = creationflags
    elif os.name != "nt":
        kwargs["start_new_session"] = True
    command = [RAWR_EXE, "run", model, prompt,
               "--max-tokens", str(max_tokens), "--temperature", str(temperature)]
    if os.name == "nt" and RAWR_EXE.lower().endswith((".cmd", ".bat")):
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", RAWR_EXE, *command[1:]]
    proc = await asyncio.create_subprocess_exec(
        *command,
        **kwargs,
    )
    entry = OwnedProcess(request_id, proc, _create_windows_job(proc.pid), time.monotonic())
    async with _active_processes_lock:
        _active_processes[request_id] = entry
    await _record_process_event("started", entry, job_owned=bool(entry.job_handle))

    communicate = asyncio.create_task(proc.communicate())
    try:
        while not communicate.done():
            done, _ = await asyncio.wait({communicate}, timeout=0.25)
            if done:
                break
            try:
                if await request.is_disconnected():
                    raise InferenceCancelled()
            except AttributeError:
                # Test doubles and older ASGI adapters may not expose this API.
                pass
        stdout, stderr = await communicate
        output = stdout.decode(errors="replace") if isinstance(stdout, bytes) else (stdout or "")
        if not output.strip():
            output = stderr.decode(errors="replace") if isinstance(stderr, bytes) else (stderr or "")
        if proc.returncode not in (0, None) and not output.strip():
            output = f"Error: rawr.exe exited with code {proc.returncode}"
        return _extract_generation_text(output)
    except asyncio.CancelledError:
        # The ASGI task is being cancelled because the client disconnected.
        # Cleanup is performed in the shielded finally block below; record the
        # reason without making cleanup depend on the cancelled task.
        asyncio.create_task(_record_process_event("cancelled", entry))
        raise
    except InferenceCancelled:
        await _record_process_event("cancelled", entry)
        raise
    finally:
        async def finalize() -> None:
            if not communicate.done():
                communicate.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await communicate
            if proc.returncode is None:
                await _terminate_owned(entry)
            else:
                _close_windows_job(entry.job_handle)
            async with _active_processes_lock:
                _active_processes.pop(request_id, None)
            await _record_process_event("reaped", entry, exit_code=proc.returncode)

        cleanup_task = asyncio.create_task(finalize())
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            # Keep cleanup alive after the request task has been cancelled.
            cleanup_task.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)


async def _run_with_timeout(
    request: Request, request_id: str, model: str, prompt: str,
    max_tokens: int, temperature: float,
) -> str:
    try:
        return await asyncio.wait_for(
            _run_owned_inference(request, request_id, model, prompt, max_tokens, temperature),
            timeout=INFERENCE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        # _run_owned_inference's finally block reaps the process tree.
        return "Error: Model generation timed out"


@app.get("/api/inference/active")
async def inference_active() -> Dict[str, Any]:
    async with _active_processes_lock:
        active = [
            {"request_id": e.request_id, "pid": e.process.pid,
             "started_at": e.started_at, "job_owned": bool(e.job_handle)}
            for e in _active_processes.values()
        ]
    return {"active": active, "count": len(active)}


@app.get("/api/inference/events")
async def inference_events() -> Dict[str, Any]:
    async with _process_events_lock:
        return {"events": list(_process_events)}


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/models")
async def list_models() -> Dict[str, Any]:
    try:
        result = subprocess.run(
            [RAWR_EXE, "list"],
            capture_output=True, text=True, timeout=30,
        )
        models: List[str] = []
        for line in result.stdout.splitlines():
            line = line.strip().strip('"')
            if not line:
                continue
            low = line.lower()
            if low.startswith(("model", "ollama", "directory", "store", "==")):
                continue
            if len(line) >= 2 and line[1] == ":":
                continue
            if ":" in line:
                models.append(line)
        if not models:
            models = [DEFAULT_MODEL, "qwen3:8b"]
    except Exception:
        models = [DEFAULT_MODEL, "qwen3:8b"]

    now = int(time.time())
    return {
        "object": "list",
        "data": [
            ModelInfo(id=m, created=now).model_dump() for m in models
        ],
    }


@app.get("/api/tags")
async def api_tags() -> Dict[str, Any]:
    """Ollama-compatible /api/tags alias for Copilot health probes."""
    return await list_models()


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Any:
    body = await request.json()
    request_id = request.headers.get("x-request-id") or f"req-{uuid.uuid4().hex[:12]}"

    requested_model = body.get("model") or DEFAULT_MODEL
    try:
        model = resolve_model(requested_model)
    except ValueError as exc:
        return _build_response(requested_model, f"Error: {exc}")

    messages = body.get("messages") or []
    stream = bool(body.get("stream", False))
    temperature = body.get("temperature", 0.2)
    max_tokens = body.get("max_tokens", 128)

    if not messages:
        return _build_response(requested_model, "Error: No messages provided")

    user_messages = [m for m in messages if m.get("role") == "user"]
    if not user_messages:
        return _build_response(requested_model, "Error: No user message found")
    prompt = user_messages[-1].get("content", "")

    if not stream:
        try:
            async with inference_lock:
                content = await _run_with_timeout(
                    request, request_id, model, prompt, int(max_tokens), float(temperature)
                )
        except InferenceCancelled:
            return JSONResponse(status_code=499, content={
                "error": {"type": "request_cancelled", "request_id": request_id}
            })
        except asyncio.CancelledError:
            raise
        response = _build_response(requested_model, content)
        response["model"] = requested_model
        return response

    # Streaming: emit SSE chunks then [DONE]
    async def event_stream():
        try:
            async with inference_lock:
                content = await _run_with_timeout(
                    request, request_id, model, prompt, int(max_tokens), float(temperature)
                )
            words = content.split()
            for i, word in enumerate(words):
                if await request.is_disconnected():
                    raise InferenceCancelled()
                delta = {"content": word + " "} if i < len(words) - 1 else {"content": word}
                chunk = _build_chunk(requested_model, delta, None)
                yield f"data: {json.dumps(chunk)}\n\n"
            final = _build_chunk(requested_model, {}, "stop")
            yield f"data: {json.dumps(final)}\n\n"
            yield "data: [DONE]\n\n"
        except InferenceCancelled:
            # The ASGI server may already have closed the socket.  Do not try
            # to write an error frame; cleanup has already completed.
            return
        except asyncio.CancelledError:
            raise

    return StreamingResponse(event_stream(), media_type="text/event-stream")


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=11436)
