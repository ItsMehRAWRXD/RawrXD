# Deep2 native inference flight recorder

C++20, Windows API, standard library; no third-party dependencies.

## Build

From an x64 MSVC Developer PowerShell:

```powershell
cl /nologo /std:c++20 /EHsc /W4 flight_recorder_smoke.cpp /Fe:flight_recorder_smoke.exe
.\flight_recorder_smoke.exe
Get-Content .\deep2_flight.jsonl -Tail 20
```

## Integrate

Initialize `rawrxd::debug::Recorder recorder;` at process startup and call
`recorder.start(L"F:\\rawrxd\\logs\\deep2_flight.jsonl", 5000, 1000);`.
The directory must already exist. Call `recorder.stop()` on orderly shutdown.

Place `rawrxd::debug::Scope s(recorder,"prefill")` around prefill and
`s.progress(n)` only when n tokens or operations actually complete.
Add nested scopes around graph layer, tensor operation, GGUF read, dequant,
CPU GEMV, Vulkan dispatch, GPU wait, KV append, decode and tool execution.
Use `recorder.counter("gpu_dispatches", count)` at the actual Vulkan
`vkCmdDispatch` recording site, and separate counters for submit and completion.
Do not claim GPU work completed merely because a command was recorded.

## Reading logs

`begin` without matching `end` indicates a live or interrupted operation.
`no_operation_progress` indicates an active operation with no progress event.
`global_no_progress` means no recorded operation progress or completion.
`elapsed_ms` is time since the operation began, and `units` is the number
of completed work units reported by the integration.

## Limitations and safety

This is instrumentation, not a reverse-engineering disassembler or automatic
performance fix. It cannot identify an uninstrumented kernel's internals.
Progress requires explicit hooks. File I/O is synchronous and flushes every
record, so use sampling or an asynchronous bounded queue for performance tests.
The monitor observes, but does not terminate processes. A separate watchdog
must own cancellation and worker supervision. Do not log source contents,
prompts, tensor values, secrets, or arbitrary user-controlled strings.
The smoke test and production integration have not been compiled or run here.
