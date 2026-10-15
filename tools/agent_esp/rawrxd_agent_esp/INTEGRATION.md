# RawrXD Agent ESP Complete Extension (C++20, no third-party dependencies)

## What is included
- `agent_esp.hpp`: original bounded MPSC event bus and JSONL recorder (unchanged).
- `esp_metrics.hpp`: thread-safe per-request rolling TPS, decode/prefill/task TPS, TTFT, context, GPU/CPU counters, tool counters, stall detector, JSON metrics snapshot.
- `esp_runtime.hpp`: simple integration facade for Deep2/agentic events.
- `esp_cli.hpp`: live terminal event printer via recorder callback.
- `esp_demo.cpp`, `esp_test.cpp`: runnable demo and deterministic clock-based tests.

## Build and run
```powershell
cmake -S F:\rawrxd\tools\agent_esp -B F:\rawrxd\build_agent_esp
cmake --build F:\rawrxd\build_agent_esp --config Release
ctest --test-dir F:\rawrxd\build_agent_esp -C Release --output-on-failure
& F:\rawrxd\build_agent_esp\Release\agent_esp_demo.exe F:\rawrxd\agentic_ws\agentic_live.jsonl
Get-Content F:\rawrxd\agentic_ws\agentic_live.jsonl -Tail 30 -Wait
```

## Minimal Deep2 integration
```cpp
#include "esp_runtime.hpp"
#include "esp_cli.hpp"
rawrxd::esp::Bus bus(16384);
rawrxd::esp::ConsoleView cli;
rawrxd::esp::Recorder recorder(bus, log_path, [&](const rawrxd::esp::Event& e){ cli(e); });
if (!recorder.start()) { /* report failure, optionally disable recording */ }
rawrxd::esp::RuntimeESP esp(bus, request_id, agent_id);
esp.model_load(model_path);
esp.tokenizer(tokenizer_ok);
esp.prefill_start(prompt_token_count, context_token_count);
// ACTUAL prefill execution...
esp.prefill_end();
esp.decode_start();
// In ACTUAL decode callback: esp.token(token_id, redacted_fragment);
// Timer/UI thread every 250-500ms: esp.tick();
// Tool boundary: esp.snap(reason); esp.tool_start(safe_tool_description);
// After actual execution: esp.tool_result(safe_result, exit_code);
// Build/test hooks: esp.build_start(...), esp.build_result(exit_code), etc.
esp.finish(host_verified_success);
recorder.stop();
```

## CLI command routing (must be added to actual `rawr` parser)
Suggested syntax: `rawr run modelname "task" --esp=tps` or `--esp=verbose`.
The source does not modify your `rawr.exe`. In `rawr run`, construct a Recorder and ConsoleView and pass the same RuntimeESP/Bus to the engine and tool host. A CLI switch only changes rendering; never disable evidence recording unintentionally.

## Native Win32 ESP panel (must be added to actual IDE source)
Use recorder callback to post a heap-owned `Event` to the existing `WM_APP+100` UI dispatcher. UI thread owns deletion. Never manipulate HWND controls from worker threads. Update the TPS display from a 250ms timer by reading `metrics.snapshot()`, not from each token. Track request/agent IDs. Render phase as `TOOL`/`BUILD`/`TEST` rather than 0 TPS when the model is not decoding. Use a bounded list view and show dropped event count.

## Correctness notes
- Prefill TPS is prompt tokens / cumulative prefill seconds. During an ongoing prefill, the displayed count is only completed prefill tokens; do not label it live instantaneous prefill speed without a processed-token counter.
- Decode TPS is total generated tokens / cumulative decode seconds. Rolling TPS is generated tokens in last five seconds / min(5 seconds, time in current decode segment).
- TTFT measures from `model_load`/task_start to first generated token, including loading and prefill. For per-request TTFT without load, call `task_start` at request submission.
- Task TPS includes all tool and build time. It is NOT model inference TPS.
- Stall detection applies to load/prefill/decode only. For long GPU operations, emit progress events or use a stage-specific timeout; the default is 30s.
- Event bus is bounded and may drop events under load. Show `bus.dropped()` in UI. Avoid per-token raw output if it contains secrets.
- Recorder flushes each event; heavy token telemetry may reduce TPS. For high throughput, batch writes and snapshots and benchmark overhead.
- Recorder callbacks run on the consumer thread. They must be fast and must not throw. A thrown callback exception can terminate the process; catch errors at the integration boundary.
- No independent evidence of actual GPU utilization is possible from these counters alone. Increment GPUDispatch/CPUFallback only in actual runtime dispatch paths.
- JSONL snapshots are nested as JSON strings in `message` to preserve compatibility with existing ESP JSONL readers.
- Windows native IDE, MSVC, rawr CLI, and actual Deep2 hooks remain unverified by this package.
