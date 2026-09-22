# SCREENPILOT_LOCAL_AGENT_E2E_FINAL_AUDIT

## Scope

Authority source audited: the supplied 30,442-line `ide_chatbot.html` snapshot.

This audit intentionally separates:

1. **Core ScreenPilot agent shipping path**
2. **Privileged specialty panels**
3. **LABS / Multi-Window simulation debt**
4. **Repository-specific LocalServer / Agent Coordinator integration**

The public homepage coherence receipt is a separate work unit and does not prove
local agent execution.

## P0 shipping blockers found in the supplied HTML

### P0-1 — No production ScreenPilot V1/V2 API consumer

The supplied page had no `/api/v1/screenpilot/*` consumer. Main chat used the
historical OpenAI-compatible `/v1/chat/completions` path and the browser itself
owned the agent tool loop.

**Fixed in this drop:** main `sendToBackend()` is overridden fail-closed to
`/api/v1/screenpilot/agent/run`.

### P0-2 — Browser-owned tool authority

The historical non-streaming agent loop called
`/api/agent/execute-tool` directly from JavaScript and re-queried the model.

That is a second authority implementation and can diverge from native IDE/CLI.

**Fixed for the shipping agent path:** browser sends one agent request; the
server-owned canonical coordinator owns tool iteration.

### P0-3 — Streaming tool calls were rendered, not executed

The historical streaming path accumulated OpenAI tool-call deltas and rendered
tool cards, but did not enter the real execution loop.

**Fixed:** streaming now transports server-owned agent events. Tool execution
does not depend on whether the UI chose streaming.

### P0-4 — Privileged `postMessage` test harness

The supplied page included a message bridge with arbitrary named global calls
plus `new Function(...)`. It also accepted `Origin: null`.

**Fixed:** removed from the shipping HTML. HTTP certification gates replace it.

### P0-5 — CSP incompatible with privileged local agent

The supplied CSP allowed:
- `'unsafe-eval'`
- external CDN JavaScript/styles/fonts
- any localhost port in `connect-src`
- file/blob default sources

**Fixed:** no `'unsafe-eval'`, no CDNs, same-origin connect policy, object/base
restrictions. `'unsafe-inline'` remains because this legacy single-file UI has
many inline event handlers and styles; removing it is a separate HTML
refactor, not required for the canonical authority boundary.

### P0-6 — File:// privileged mode

A file:// page had broad localhost connectivity and the test harness tolerated
null origins.

**Fixed:** shipping authority client rejects file://. Final URL is:
`http://127.0.0.1:11435/screenpilot`.

### P0-7 — Mode authority could be self-granted by the browser

The legacy page used `State.agenticMode` inconsistently as both boolean and
string.

**Fixed:** V2 server derives permissions from the requested mode:
- ASK: read/search/git-read
- PLAN: read/search/git-read
- BUILD: ASK + workspace write/build/test
- AGENT: BUILD + process/git-write/model-control, with elevated operations
  requiring explicit approval

The browser cannot send a permission mask.

### P0-8 — Workspace validation only at request boundary is insufficient

Even if the initial workspace is valid, an absolute file path or process
command can escape it later.

**Fixed contract:** `screenpilot_tool_policy_v2.h` requires each path-bearing
tool invocation to be checked against the canonical workspace. Process-general
tools require a second command policy because cwd alone is not confinement.

### P0-9 — No approval handshake

The first in-process drop had cancellation but no interactive approval path for
network, Git remote, or host-destructive actions.

**Fixed:** V2 adds `approval_required` stream events and
`POST /api/v1/screenpilot/agent/approve`.

### P0-10 — Legacy privileged routes remain callable by specialty panels

The page contains many direct `/api/cli`, hotpatch, extension, model, browser,
debugger, and tool requests.

**Fixed contract, repository hook still required:** same ScreenPilot session
must guard browser-originated privileged legacy routes, and each route must
either enter canonical Tool Authority or be disabled for browser callers.

See `integration/LEGACY_BROWSER_ROUTE_POLICY.md`.

## P1 correctness issues fixed

- Startup toolbar claimed `Agent: ON` while state was false.
- Client max input length was effectively 1 GB.
- Generated assistant code action buttons depended on sanitizer-permitted
  `onclick`.
- Direct Ollama / alternate-port fallback could bypass RawrXD authority.
- Multi-Window compiler returned `Build OK` after a timer.
- Multi-Window generic RE action did not perform analysis.
- HTML-only MASM kernel fallback contained no-op IPC/unregister/task behavior.

The final client:
- delegates generated code actions through one DOM event listener,
- caps prompt input client-side at 4 MiB,
- locks authority to same-origin RawrXD,
- overrides Multi-Window compile and generic RE actions through canonical agent
  requests,
- labels the browser kernel fallback honestly as non-native and gives it
  functional scheduling/cancel/registration/IPC bookkeeping.

## P2 / LABS debt intentionally not certified as core completion

These features are not required to certify the local HTML agent itself:

1. Multi-Window `stopSwarm()` does not have true per-window AbortController
   ownership in the original implementation.
2. Multi-Window `chainAll()` advances on a fixed timeout instead of awaiting
   each model result.
3. RE Deobfuscator reports client-side heuristic results rather than a native
   analyzer.
4. Memory scanner is instructional unless a privileged backend implementation
   is connected.
5. Many advanced specialty panels still use historical endpoint-specific
   contracts.

Do not advertise those individual LABS operations as fully authoritative until
their route-level gates are green.

## Repository-specific blockers that cannot be truthfully completed from HTML

Exactly three source mappings require the RawrXD C++ repository:

1. Existing LocalServer request/response types -> V2 HTTP adapter.
2. V2 `run_agent` callback -> exact canonical Agent Coordinator entrypoint.
3. Static routes:
   - `/screenpilot`
   - `/screenpilot/screenpilot_authority.js`

Additionally, legacy privileged routes must receive the session + Tool
Authority middleware described above.

## Required final runtime gates

Static:
- `python tests/static_audit.py`

Protocol:
- `tests/certify_screenpilot_e2e.ps1`

Mutation:
- `tests/certify_mutation.ps1`

Approval:
- paste `tests/approval_gate_prompt.txt` in AGENT mode and DENY the request.

Shipping manual:
- launch the actual `RawrXD-Win32IDE.exe`
- open `/screenpilot`
- verify ASK/PLAN/BUILD/AGENT
- perform a disposable workspace mutation
- cancel an in-flight request
- deny an approval-gated operation
- close/relaunch IDE and repeat with no smoke/test environment variables

## Completion rule

Do not mark `SCREENPILOT_LOCAL_AGENT_E2E=PASS` merely because the HTML loads or
the API route answers.

PASS requires:

`browser UI -> :11435 -> canonical coordinator -> canonical Tool Authority ->
real local model -> real tool action -> streamed receipt -> browser`

with no alternate browser-owned execution path.
