# Deep2Backend is an HTTP adapter, not in-process — 2026-21

Sprint gate: **why does GUI Deep2 return "Deep2 server returned empty response"?**

## Root cause (source)

`src/agentic/Deep2Backend.cpp`

```cpp
InferenceResult Deep2Backend::ChatSync(...) {
    if (!m_initialized.load()) return InferenceResult::Error("Deep2 backend not initialized");
    ...
    std::string resp = makePostRequest("/v1/chat/completions", req.dump());
    ...
    if (resp.empty()) {
        RecordFailure("Deep2 ChatSync: empty response");
        return InferenceResult::Error("Deep2 server returned empty response");
    }
```

`Deep2Backend` is an **HTTP client adapter**:

* `LoadModel()` POSTs to `/api/models/load` on a Deep2 **server**.
* `ChatSync()` POSTs to `/v1/chat/completions` and parses an OpenAI-style body.
* `ListModels()` reads `/v1/models` or `/api/models`.

With no Deep2 server listening (the run had `llama-server` stopped and no Deep2 HTTP
endpoint), `makePostRequest` returns an empty string and `ChatSync` returns exactly the
observed error. No native `Deep2Engine`/`Deep2Bridge` call is present on this path.

## Consequence

The agentic router's `deep2` backend is an **HTTP transport**, not the in-process engine.
That contradicts the serverless/in-process objective and means:

* `BACKEND_ROUTER_SELECTED kind=deep2 mode=deep2 failover=0` proves only that the
  router selected the HTTP adapter — not that any inference ran.
* `GPU GEMV Dispatches: 0` in the same run is consistent with this: no local engine
  was used.

## Correct fix (in-process, preferred)

Intercept explicit Deep2 at the agentic routing boundary and call the existing native
lifecycle instead of the router:

* `Win32IDE::deep2Bridge()` accessor was added in `38a9b8bb05`/`patch_agentic_deep2.py`
  (header-only, public, read-only).
* `AgenticBridge::Chat` should, when `RAWRXD_CHAT_BACKEND == "deep2"`, use
  `m_ide->deep2Bridge()->LoadModel(path)` + `GenerateStream(...)` and return the text,
  never touching `ChatViaBackendRouter`.

Alternative (larger): give `Deep2Backend` an in-process implementation behind the same
`ChatSync` contract, so the router remains the single entry point.

## Do not

* Start a Deep2 HTTP server just to satisfy the adapter — that reintroduces the
  external-process dependency the serverless design removes.
* Substitute placeholder text or retry Ollama.

## Verified state

```
Deep2Backend::ChatSync -> makePostRequest("/v1/chat/completions") -> empty
error: "Deep2 server returned empty response"
router proof: BACKEND_ROUTER_SELECTED kind=deep2 mode=deep2 failover=0
no [BRIDGE_GEN]/[BRIDGE_STREAM]; GPU GEMV Dispatches 0
```

## Next (exact)

1. Add a `[CHAT_DEEP2_NATIVE]` marker in `AgenticBridge::Chat` before the router call,
  then implement the in-process branch there.
3. Acceptance: transcript delta > 0, `[BRIDGE_STREAM] gemv_ok>0`, queue submits > 0, and
  zero HTTP requests to any Deep2 endpoint.