# YOLO-POLICY-001 — auto-approval audit — 2026-11-21

Sprint gate: **prove that switching automatic approval changes authorization only**

## Finding 1 — the policy is a POD, so it cannot allocate model memory

`src/win32app/Win32IDE_AutonomousLoop.h:66-73`

```cpp
struct LoopPolicy {
    bool  allowShell        = false;  // run_shell / apply_diff
    bool  allowWrite        = true;   // write_file
    bool  allowRead         = true;   // read_file, list_dir, search_workspace
    int   maxSteps          = 20;
    int   maxOutputBytes    = 256 * 1024;
    bool  autoApproveWrites = false;  // skip confirm for write_file
};
```

Three bools and two ints. No pointers, no handles, no engine references. Toggling any field
cannot allocate weights, KV cache, context, or an inference session.

## Finding 2 — the approval gate

`src/win32app/Win32IDE_AutonomousLoop.cpp:182`

```cpp
tool.name == "write_file" && m_policy.autoApproveWrites
```

The flag is read only at the tool-dispatch boundary for `write_file`. `SecurityGate` and
`ToolCallBridge::ExecuteToolCall` are untouched by this check.

## Finding 3 — the flag is never assigned anywhere

```
rg -rn "autoApproveWrites" src tools
  Win32IDE_AutonomousLoop.h:72    (declaration, default false)
  Win32IDE_AutonomousLoop.cpp:182 (read)
```

No assignment, no settings load, no menu handler. Therefore:

* **there is no user-facing YOLO toggle in this tree**;
* `autoApproveWrites` is permanently `false`, so `write_file` always requires approval;
* `allowShell` is also permanently `false`.

`RAWRXD_AUTO_APPROVE` (src/agent/zero_touch.cpp:61,122) is a separate mechanism: an
environment variable set for child processes, not a UI setting, and not linked to
`LoopPolicy`.

## Acceptance contract — assessed

```
YOLO_POLICY_IMPLEMENTATION=EXISTING (LoopPolicy + autoApproveWrites)
NEW_MODEL_INSTANCE=0            (no engine/model type in LoopPolicy)
NEW_MODEL_LOAD=0                (no load path in the approval branch)
NEW_KV_CACHE=0                  (no cache type in LoopPolicy)
NEW_INFERENCE_SESSION=0         (no session in the approval branch)
NEW_BACKGROUND_WORKERS=0        (flag is read at dispatch only)

DELTA_MODEL_MEMORY=0            (POD policy; by construction)
DELTA_SCHEDULER_FREQUENCY=0     (no scheduler interaction)
DELTA_IDLE_GPU_SUBMISSIONS=0    (no GPU interaction)

AUTO_APPROVAL=EXISTING_POLICY_ONLY
SECURITY_GATE=UNCHANGED
```

## Caveats — not measured at runtime

* No before/after VRAM or submission measurement was taken; the invariants above follow
  from the type and the call site, not from a profiled delta.
* `DELTA_MODEL_MEMORY=0` is a **source-level** result. A runtime receipt would require a
  probe that toggles the flag in-process, which is impossible today because nothing sets it.
* The three mechanisms (`autoApproveWrites`, `AutoApproved`, `RAWRXD_AUTO_APPROVE`) are
  independent; this audit does not unify them, per scope.

## Conclusion

YOLO is a policy/resource non-issue in this tree: the approval flag is a POD field read at
the tool boundary, no model or GPU resource is associated with it, and there is no UI
control that changes it. The gap is **product scope** (no user-facing toggle, and
auto-approval covers `write_file` only), not resource cost.

No source change was made. No permission scope was expanded.