# Deep2 first-progress watchdog (Windows / C++20 / no external dependencies)

## Policy
- At 30 seconds after Watchdog construction, cancel only if **zero** verified progress events have occurred across **all** instrumented functions.
- Once any function demonstrates actual progress, the startup gate is satisfied permanently. Other functions need not start.
- The existing 600-second total wall deadline remains independent.
- No implicit later idle timeout: this is intentionally **not** a 30-second per-function timeout.
- Progress is completion of a layer, prefill token, GPU submission (after fence confirms completion), generated token, tool, build, test, or verification step. Merely entering a function or logging `prefill_start` is not progress.

## Build smoke test (Developer Command Prompt)
`cl /nologo /std:c++20 /EHsc /W4 watchdog_smoke.cpp /Fe:watchdog_smoke.exe`
`watchdog_smoke.exe`

## Wiring
Construct one Watchdog **before** starting model initialization. Start its monitoring thread, then call `Progress(Activity::...)` at the actual completion sites. For example:

```cpp
rawrxd::watchdog::Watchdog wd({30000,600000,100});
wd.Start([&](rawrxd::watchdog::Status s) {
    // Thread-safe: set a cancellation flag consumed by the executor.
    // Emit ESP watchdog_timeout with s.state and s.elapsedMs.
    engineCancellationRequested.store(true, std::memory_order_release);
});
// At real graph execution site, after a layer completes:
wd.Progress(rawrxd::watchdog::Activity::ModelLayer);
// At token-commit site:
wd.Progress(rawrxd::watchdog::Activity::PrefillToken);
// At successful tool dispatch completion:
wd.Progress(rawrxd::watchdog::Activity::ToolCompleted);
// On normal termination:
wd.Finish(); wd.Stop();
```

`engineCancellationRequested` is a placeholder for your existing cancellation token. The watchdog never invokes arbitrary non-thread-safe executor methods from its monitor thread. The agent loop must poll the cancellation token. If a blocked worker does not respond, use your existing verified process supervisor/Job Object to stop the isolated child after a grace period, not TerminateThread. Keep job handle ownership outside this watchdog.

## Caveats
- First-progress detection does not establish GPU usage or good TPS. Instrument GPU/CPU execution separately.
- A very slow operation with no intermediate completion can time out even when legitimately computing; instrument layer or GPU fence completions if you want to permit that workload.
- A completion event must not be fabricated by a periodic timer/heartbeat.
- The watchdog starts at object construction, so construct it immediately before launch, not minutes before.
- If a timeout callback captures local variables, ensure they outlive Stop().
