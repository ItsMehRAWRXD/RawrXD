# RAWRXD_CONTINUOUS_EXECUTION_001

Purpose: make loaded-model execution in the IDE progress by **work events**, never by wall-clock/TPS/tick state. A request has exactly one terminal outcome: EOS/stop sequence/user token limit/cancel/error. "No response" is not a state.

## What this drop changes

1. **No timer-controlled runtime state**
   - no `Sleep`
   - no `wait_for` / `wait_until`
   - no elapsed-time timeout
   - no TPS threshold used to continue/stop
   - no `GetTickCount*` / `QueryPerformanceCounter` used for control
   - no watchdog timer that mutates model state

2. **No scheduler token-credit hard stop**
   The controller does not inspect any global token budget. Token limits are either:
   - `Request::max_output_tokens == 0` -> unlimited by controller, or
   - an explicit caller/user cap.

   Admission policy can decide whether to START a request. Once started, scheduler bookkeeping must not silently convert a live request into "no response".

3. **Real model binding only**
   `ModelBindings` requires real `prefill`, `decode_one`, `append_tool_result`, and `cancel` functions. Missing operations are rejected. There is no synthetic response, fake token generator, timeout success path, or stub fallback.

4. **Streaming is push/event driven**
   The inference worker publishes every text delta immediately into `EventPipe`. The Win32 bridge consumes the pipe on a dedicated thread and uses `PostMessageW`; inference never waits for paint/layout/chat controls.

5. **Agent/tool continuation is one run**
   A model tool call transitions:
   `Decode -> ToolRunning -> ResumeAfterTool -> Decode`.
   The tool result is appended into the real model context, and decoding continues. A tool failure is emitted as an explicit `Error + Completed`, not a hung run.

6. **Fine-grained Deep2 progress**
   Wire `ModelBindings::set_progress_sink` to Deep2 so it emits progress after irreversible work units:
   - layer completion
   - expert completion/cache resolve
   - GPU range submission/completion
   - cross-GPU handoff
   - KV advance
   - logits complete
   - sampled token

   These are work epochs, not timer pulses.

## Required integration into Deep2Engine

The existing Deep2 path already has the token sequence:
`embedToken -> forwardTokenAllLayers -> kvCache->advance -> computeLogits -> sampleToken`.

Expose that as one real decode step instead of wrapping the old whole-response function.

### Required engine members

Add a decode cursor owned by the request/session, not global wall-clock state:

```cpp
struct Deep2DecodeCursor {
    std::vector<float> hidden;
    std::vector<float> logits;
    uint32_t pendingToken = 0;
    bool pendingForward = false;
    uint64_t generated = 0;
    uint64_t workEpoch = 0;
    bool cancelRequested = false;
};
```

Add engine entry points (names may be adjusted to existing class naming, behavior must remain):

```cpp
bool beginContinuousTurn(std::string_view prompt,
                         Deep2DecodeCursor& c,
                         std::string& error);

rawrxd::continuous::DecodeResult
decodeContinuousOne(Deep2DecodeCursor& c);

bool appendContinuousToolResult(Deep2DecodeCursor& c,
                                std::string_view toolName,
                                std::string_view toolResult,
                                std::string& error);

void cancelContinuous(Deep2DecodeCursor& c);
```

### decodeContinuousOne body contract

The body must execute the existing real operations, in this order, with NO timeout branch:

```cpp
if (c.cancelRequested) return cancelled_as_error_or_controller_cancel();

if (c.pendingForward) {
    embedToken(c.pendingToken, c.hidden.data());

    if (!forwardTokenAllLayers(c.hidden.data(), seqLen)) {
        return backend_error("forwardTokenAllLayers failed");
    }
    ++c.workEpoch;
    progress(c.workEpoch, currentLayer, numLayers, "forward");

    kvCache->advance();
    ++c.workEpoch;
    progress(c.workEpoch, 0, 0, "kv_advance");

    c.pendingForward = false;
}

computeLogits(c.hidden.data(), c.logits);
++c.workEpoch;
progress(c.workEpoch, 0, 0, "logits");

const auto nextTok = sampleToken(c.logits);
++c.workEpoch;
progress(c.workEpoch, 0, 0, "sample");

if (isEos(nextTok)) return DecodeResult{DecodeKind::Eos};

// Use the REAL tokenizer/token decoder. Do not stringify the integer token id.
std::string piece = decodeTokenPiece(nextTok);

c.pendingToken = nextTok;
c.pendingForward = true;
++c.generated;

return DecodeResult{DecodeKind::Text, nextTok, std::move(piece)};
```

The exact token-piece decoder and chat-template/tool parser must be the engine's existing real implementations. Do not add a fake `std::to_string(token)` fallback.

## Bind it when the IDE loads a model

Create one cursor per chat/agent run. Do not share mutable decode cursor state between sessions.

```cpp
auto cursor = std::make_shared<Deep2DecodeCursor>();

rawrxd::continuous::ModelBindings b;

b.prefill = [&engine, cursor](std::string_view prompt, std::string& error) {
    return engine.beginContinuousTurn(prompt, *cursor, error);
};

b.decode_one = [&engine, cursor] {
    return engine.decodeContinuousOne(*cursor);
};

b.append_tool_result = [&engine, cursor](std::string_view name,
                                         std::string_view result,
                                         std::string& error) {
    return engine.appendContinuousToolResult(*cursor, name, result, error);
};

b.cancel = [&engine, cursor] {
    engine.cancelContinuous(*cursor);
};

b.set_progress_sink = [&engine](auto sink) {
    engine.setContinuousProgressSink(std::move(sink));
};
```

No callback above may point to a placeholder. If a required Deep2 function does not exist yet, implement it from the existing decode code before wiring this controller.

## Win32 UI ownership

At IDE initialization:

```cpp
controller = std::make_unique<rawrxd::continuous::Controller>();
streamBridge = std::make_unique<rawrxd::continuous::Win32EventBridge>(
    controller->events(), hwndMain);
streamBridge->start();
```

On Send / Agent Run / Autonomous Run:
- construct real Deep2 bindings for the currently loaded model
- build the real tool registry for the selected authority
- call `controller->start(...)`
- keep the returned `RunId` on the chat turn

Window procedure:

```cpp
case rawrxd::continuous::Win32EventBridge::kDefaultMessage: {
    std::unique_ptr<rawrxd::continuous::Event> ev(
        reinterpret_cast<rawrxd::continuous::Event*>(lParam));

    switch (ev->kind) {
    case EventKind::TextDelta:
        chat.AppendAssistantDelta(ev->run_id, ev->text);
        break;
    case EventKind::Progress:
        chat.SetWorkProgress(ev->run_id, ev->work_epoch,
                             ev->layer_index, ev->layer_count, ev->text);
        break;
    case EventKind::Error:
        chat.ShowRunError(ev->run_id, ev->text);
        break;
    case EventKind::Completed:
        chat.MarkRunTerminal(ev->run_id, ev->finish);
        break;
    default:
        break;
    }
    return 0;
}
```

The UI may animate an indeterminate glyph for presentation, but animation timing must never drive model/session state.

## Remove / demote the existing hard-stop gates

The current swarm budget check must not be called from a running model turn as a generation continuation predicate.

Bad:
```cpp
if (!rxd_token_budget_reserve(agent, tokens))
    return; // silent non-response / frozen-looking turn
```

Required:
- token budget may reject **admission before `Controller::start`**, OR
- it may record/account tokens after generation,
- but it must not silently stop a started response.
- if policy intentionally stops a run, emit a typed terminal error/event.

Similarly, `vulkanStrictNoCpuFallback_` is allowed to fail closed, but its failure must become a streamed backend error and terminal completion. It must not leave the UI waiting for a token that will never arrive.

## Autonomous/agentic continuation rule

A run continues until exactly one of:
- model EOS
- real stop sequence
- explicit caller token limit
- explicit user/system cancellation
- real backend/tool/protocol error

A run does **not** terminate because:
- elapsed time
- no token arrived "recently"
- TPS fell below a threshold
- UI stopped repainting
- scheduler credit changed after admission
- GPU telemetry tick did not change
- a benchmark measurement window ended

## Liveness boundary

No software can prove that an arbitrary external tool/driver/kernel that has entered a permanent deadlock will eventually return **without** either:
- a timeout/time-based recovery policy, or
- an external cancellation/kill action.

This drop therefore guarantees that RawrXD itself does not use time to stop/advance a run and does not freeze its UI on inference. External tool calls should run out-of-process if you need hard isolation from a hung third-party process. Their completion remains event-driven.

## Build integration

Add:
- `continuous_execution.cpp`
- `win32_event_bridge.cpp`

to the Win32 IDE target and include this directory.

No third-party libraries are required.

## Static rejection checks

These should return no matches in this drop:

```powershell
Select-String -Path .\*.cpp,.\*.hpp -Pattern `
  'Sleep\(|sleep_for|sleep_until|wait_for|wait_until|GetTickCount|QueryPerformanceCounter'

Select-String -Path .\*.cpp,.\*.hpp -Pattern `
  'TPS.*stop|timeout.*state|token_budget.*return'
```

The presence of telemetry timing elsewhere in Deep2 is fine only if it is observational and cannot mutate execution state.
