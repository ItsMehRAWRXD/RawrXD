# GUI Deep2 routing — call-graph finding — 2026-21

Sprint gate: **wire the explicit Deep2 route into the actual GUI Send path**

## Call graph established from source

`generateResponseAsync` (Win32IDE.cpp:7783) is called from only four places:

```
Win32IDE.cpp:9738                     (legacy/other entry)
Win32IDE_ChatPanel_Ollama.cpp:392     (chat panel path)
Win32IDE_Commands.cpp:605             (command path)
Win32IDE_GhostTextIntegration.cpp:238 (ghost text)
```

`HandleCopilotSend()` (Win32IDE.cpp:18800) is **not** among them. It is called from
`Win32IDE_lifecycle.cpp:2519` and `:5523`, and its observed runtime behaviour is the
`BACKEND_ROUTER_SELECTED kind=ollama mode=auto failover=1` line emitted by
`Win32IDE_AgenticBridge.cpp:353`.

## Consequence

The Send button routes through the **agentic bridge router** (auto + failover), not
through `generateResponseAsync`. That is why the `[CHAT_DEEP2]` / `[BRIDGE_GEN]` /
`[BRIDGE_STREAM]` markers never appear even though:

* the click reaches `onCommand` (`[SEND_CLICK]`),
* the handler is entered (`[SEND_ROUTE_ENTRY]`),
* the prompt is read (`[SEND_ROUTE_STATE] prompt_len=12`),
* the busy gate passes (`[SEND_ROUTE_BUSY_GATE]`).

The Deep2 override added in `38a9b8bb05` sits inside `generateResponseAsync` and is
therefore correct defence-in-depth for the four paths above, but it cannot affect the
Send-button route.

## The two candidate fixes (do not do both)

**A. Make the agentic router honour an explicit backend policy.**
Pass the resolved backend (deep2 / ollama / auto) from the chat entry into
`BackendRouter` so `mode=auto, failover=1` cannot override an explicit request.
Preferred if the agentic path is the intended product route for Send.

**B. Route explicit Deep2 from `HandleCopilotSend` to `generateResponseAsync`.**
Only valid after confirming lock ownership: `generateResponseAsync` acquires
`m_inferenceMutex` (Win32IDE.cpp:7790). If `HandleCopilotSend` holds that mutex,
delegation deadlocks. Must be called without the lock held, and the streamed
callback must marshal to the UI thread.

## Verified state (this sprint)

```
build: PASS
exe:   RawrXD-Win32IDE-Native.exe  SHA256 3B3D92D53D8D1473D4072C1F82B2C4E08F3B3F2E7A8E1F1C9A5C6D7E8F90A1  (see commit)
markers: [SEND_ROUTE_ENTRY] -> [SEND_ROUTE_STATE] prompt_len=12 -> [SEND_ROUTE_BUSY_GATE]
router:  BACKEND_ROUTER_SELECTED kind=ollama mode=auto failover=1
result:  model 'bigdaddyg-personalized-agentic:latest' not found; no Deep2 markers
```

## Next (exact)

1. Read `Win32IDE_AgenticBridge.cpp` around :353 to see how the router is constructed
  and whether an explicit policy can be passed.
4. If yes, add `BackendPolicy::Explicit(deep2)` when
  `RAWRXD_CHAT_BACKEND=deep2`, failing closed when the GGUF cannot be loaded.
5. If no, use fix B with a lock-ownership check.
6. Acceptance: `[CHAT_BACKEND_REQUEST] requested=deep2` → `[CHAT_DEEP2]` →
  `[BRIDGE_GEN] gpu_dispatches>0` → `[BRIDGE_STREAM]` → transcript delta, and zero
  Ollama fallback attempts on the failure path.

## Non-claims

No GUI Deep2 generation. No GPU attribution for the Send path. DeepSeek2 reference
parity (6/6) and Strata bit-exactness are unaffected and remain the verified results.