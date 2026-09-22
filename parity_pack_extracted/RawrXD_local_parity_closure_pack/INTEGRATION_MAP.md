# RawrXD Local-Parity Closure Pack

This is **closure source**, not a replacement IDE, agent, Tool Authority, Deep2 runtime,
repository index, or GGUF loader. Wire it only where the shipping path lacks an equivalent.
If an equivalent already exists, keep the existing authority and use the behavior/certification
contract below as the acceptance criterion.

## Remaining-time reverse engineering

| Remaining work | Source piece / acceptance contract | Focused hours |
|---|---|---:|
| Shipping source authority | `cmake/RawrXDStrictShipping.cmake`; delete ghost/stub authority and force exactly one WinMain | 4–6 |
| Device/model CLI authority | `DevicePolicy`; parse `auto/r9700/7800xt/dual` **before** Deep2 admission | 4–6 |
| Measured scheduling | `PerformanceLedger`; route from certified local p10/median receipts, never hard-coded marketing TPS | 3–4 |
| Tool convergence | `ToolGateway`; every agent/GUI/CLI mutation flows through existing `AgentToolAuthority` adapter | 4–6 |
| Safe autonomous edits | `WorkspaceGuard` + `EditTransaction`; confine writes, atomic commit, rollback | 4–6 |
| Build/test execution | `NativeProcessRunner` + `BuildTestGate`; bounded processes, captured output, commit only after verification | 4–6 |
| Context parity | `ContextPlanner`; budget existing repository-index candidates rather than creating another index | 3–4 |
| Agent reliability | `AgentOrchestrator`; bounded plan→tool→observe loop, duplicate-action stop | 3–4 |
| Strict E2E proof | `Certification`; JSONL receipts for real shipping gates | 4–6 |
| Integration + cleanup | Replace adapters with real RawrXD types, Release build, warnings/link closure | 5–8 |
| **Total** | | **38–56** |

That intentionally targets the approximately 45–55 hour center of the prior estimate.

## Must-have parity contracts

1. **One shipping authority**
   - Exactly one `wWinMain`/`WinMain`.
   - Every production `.cpp` exists.
   - No tests/examples/benchmark/mock/fake/stub/placeholder linker-closure translation unit in
     `RawrXD-Win32IDE`, unless explicitly reviewed and allow-listed.
   - Missing contracts fail the build; do not manufacture empty compatibility units.

2. **One tool authority**
   - GUI chat, headless agent, CLI, swarm/sub-agent, and autonomous build loop invoke the same
     existing `AgentToolAuthority`.
   - No direct `system`, `_popen`, `ShellExecute`, or raw `CreateProcess` from agent surfaces.
     The single process tool implementation is allowed to use the native OS primitive.

3. **Pre-admission device selection**
   - `rawr r9700 <model> ...`, `rawr 7800xt <model> ...`, `rawr dual <model> ...`,
     and `rawr auto <model> ...` resolve before Deep2 creates its device/model session.
   - Deep2 remains authoritative for tensor/layer placement.

4. **Transactional coding**
   - Agent stages a complete multi-file change.
   - Build/tests run against the staged working tree.
   - Verification failure rolls back.
   - Successful verification is the only path to authoritative commit.

5. **Repository-aware context**
   - Reuse FileIndex/SymbolTable/AST/Search/CallGraph candidates already owned by RawrXD.
   - Rank and budget context; do not send the whole repository or construct a second index.

6. **Strict local proof**
   - Offline Release build.
   - Real local model.
   - Shipping IDE.
   - read → reason → edit → build → test → report.
   - Device selector proven.
   - Performance receipts are repeatable measured samples.

## Surpass-parity contracts

These are the pieces in this pack that can move RawrXD beyond ordinary cloud-backed AI IDE behavior:

- **Fail-closed local execution:** no cloud fallback when model/tool/runtime fails.
- **Measured heterogeneous routing:** select R9700 / 7800 XT / dual from local certified receipts.
- **Atomic autonomous repair:** a failed agent repair restores the prior tree automatically.
- **Unified receipts:** every tool call and certification gate leaves local machine-readable evidence.
- **Deterministic loop breaker:** repeated identical tool actions terminate instead of consuming context forever.
- **Strict workspace confinement:** tool paths are canonicalized and blocked if they escape the workspace.

## Wiring into RawrXD

### 1. Shipping CMake target

After the *real* `RawrXD-Win32IDE` target is defined:

```cmake
include(cmake/RawrXDStrictShipping.cmake)
rawrxd_enforce_shipping_target(RawrXD-Win32IDE)
```

Treat every resulting configure/build failure as a real ownership defect.

### 2. Existing AgentToolAuthority adapter

Implement the small `IToolAuthority` interface by delegating directly to the existing central
registry. Do **not** duplicate its registry or handlers.

```cpp
class RawrXDAuthorityAdapter final : public rawrxd::closure::IToolAuthority {
public:
    bool registered(std::string_view name) const override {
        return AgentToolAuthority::instance().hasTool(name);
    }

    rawrxd::closure::ToolResult invoke(const rawrxd::closure::ToolRequest& r) override {
        // Translate ToolRequest to RawrXD's native request type.
        // Call AgentToolAuthority::instance() here.
        // Translate the native result back.
    }
};
```

Use the exact API names that exist in the current repository; the names above are intentionally
illustrative so this drop cannot accidentally create a second authority.

### 3. CLI to Deep2

Parse device token first, build a `DevicePlan`, then pass selected adapter ordinals into the
existing Deep2 admission/session options. If RawrXD already has this exact contract, keep it.

### 4. Performance

After a strict decode run, append a `PerformanceSample`. Auto routing should consume
`summarize()` and prefer certified lower-bound (`p10`) performance rather than a projected TPS.

## Required shipping certification names

Use these exact semantic gates even if the in-repo harness uses different type names:

- `shipping_source_closure`
- `offline_release_build`
- `single_entrypoint`
- `zero_stub_authority`
- `device_selector`
- `real_model_load`
- `shipping_gui_chat`
- `repository_read`
- `transactional_edit`
- `authoritative_tool_execution`
- `build_after_edit`
- `tests_after_edit`
- `agent_final_report`
- `repeatable_performance_receipt`

A green selftest of this standalone library is **not** shipping certification. The final proof must
exercise the real `RawrXD-Win32IDE.exe`, real local model, real workspace, real build, and real tests.
