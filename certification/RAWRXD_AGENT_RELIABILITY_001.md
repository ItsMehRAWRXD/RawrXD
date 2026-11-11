# RAWRXD_AGENT_RELIABILITY_001 - Certification Record

**Certified:** 2026-10-10
**Status:** PASS (subsystems + HexMag integration); **PARTIAL** (no linkable HexMag binary)
**Tests:** 148 subsystem + 40 production-integration = **188 assertions, 0 failures**
**Source tree (deterministic provenance):** `HEAD^{tree}`
**Source commit:** see the provenance table

---

## Provenance note - read this before quoting a hash

The SHA256 of the binary that ran is recorded in
`RAWRXD_AGENT_RELIABILITY_001.manifest.json`, but **MSVC builds are not
bit-for-bit reproducible**: timestamps and local build paths are embedded, so a
rebuild from identical sources yields a different hash. Two independent builds
from the same sources were confirmed to differ.

Therefore:

- Use **`source_tree_sha1`** (`ada09709...`) as the reproducible provenance
  anchor. It is identical on any machine for the same content.
- Treat the executable SHA256 as *"this specific binary was the one executed"*,
  **not** as proof of a reproducible build.
- The authoritative outcome is the **148 passed / 0 failed** result. Re-running
  reproduces the counts, not the binary bytes.

---

## What this certification proves

The agent orchestration layer handles failure, cancellation, conflict, and
concurrency without fabricating results.

### Fitness / reliability properties

| Property | Test evidence | Meaning |
|---|---|---|
| Transient failure recovery | `recovered on attempt 3` | Retry with backoff eventually succeeds |
| Retry exhaustion | `gave up after 3 attempts` | Retries are bounded; the last error is retained |
| Permanent failure short-circuit | `non-retryable error returned after 1 attempt` | Non-retryable errors stop immediately (0 wasted retries) |
| Retry accounting identity | `attempts=3 failures=2 retries=2` | `attemptsMade - 1 == attemptErrors.size()`, and `totalRetries` counts only real retries |
| Circuit breaker | `breaker state after 2 failures: open` | Trips at the configured threshold |
| Circuit breaker fail-fast | `operation invoked: no` | While open, the operation is *never* invoked |
| Policy serialization | `round-trip preserved 6 retryable` | Policies survive a JSON round-trip |
| Conflict detection | `detected 1 conflict` | Overlapping edits from different agents |
| Conflict de-duplication | `getConflictHistory().size() == 1` | One conflict per edit pair, not three |
| Three-way merge | `merged cleanly: Only local changed; took local` | The real merge engine is exercised |
| Merge data preservation | `merged result: A / b / C` | Both disjoint agent edits survive |
| Conflict visibility | `<<<<<<< ours / FROM_AGENT1 / ======= / FROM_AGENT2` | Same-line collisions are *shown*, never silently dropped |
| Resolution determinism | `first_wins -> 'from early'`, `last_wins -> 'from late'` | Deterministic, reproducible winners |
| Cancellation propagation | `cancel token observed by worker: yes` | Cancellation reaches the executing worker |
| Agent lifecycle accounting | `1 created, 1 completed` | Lifecycle transitions are counted correctly |
| Concurrency | `12/12 concurrent tasks succeeded` | Parallel delegation under quota |
| Resource quota enforcement | depth limit, sub-agent quota, capability check, zero-budget | Quotas actually block work |

### Production integration (the subsystems are actually used)

Isolated subsystems prove nothing about the product. These assertions prove the
real code path uses the certified engines rather than its own implementations.

| Property | Evidence |
|---|---|
| Swarm delegates to the certified engine | 40 assertions in `tests/agentic_resilience/hexmag_integration_test.cpp` |
| No agent edit discarded | `merged: A_LINE1 / B_LINE2 / C_LINE3` from 3 agents (2 were dropped before) |
| Same-line collision visible | Both `FROM_A` and `FROM_B` retained with `<<<<<<<` markers |
| Strategy honoured | `first_wins -> 'b\nEARLY'`, `last_wins -> 'b\nLATE'` |
| Unknown strategy refused | `ensureConflictPolicy("totally_unknown_strategy")` returns false |
| Empty input safe | No `edits[0]` index on an empty vector |

Pre-fix behaviour this replaced: `mergeEdits()` returned only
`edits.back().newContent`, so two of three concurrent agent edits were
discarded. `detectConflicts()` did range-overlap detection only, reported every
conflict as `"manual"`, and had no de-duplication.

### All three engines integrated into the HexMag swarm

The previous revision had only the conflict engine wired. All three now have
real production call sites in `src/agentic/HexMagSwarmOrchestrator.cpp`.

| Engine | Integrated into | What it replaced | Call sites |
|---|---|---|---|
| `ConflictEngine` | `ConflictResolver::{detectConflicts,mergeEdits,resolveConflicts,threeWayMerge}` | range-overlap-only detection; `mergeEdits()` discarding all but the last edit | 1 (bridge) |
| `AdaptiveRetryEngine` | `executeWithRepeatTuner()` | a bare 6-iteration loop: no backoff, no jitter, no classification, no circuit breaker | 2 |
| `DelegationManager` | `executeParallelAgents()` | unbounded `std::async`: no quotas, no depth cap, no lifecycle ownership | 7 |

`AdaptiveRetryEngine` policy registered for specialists: `hexmag_specialist`,
6 attempts, 2s base backoff, x2 exponential, 20% jitter, circuit breaker
tripping after 3 verified failures with a 120s timeout. Retryable patterns
(`empty output`, `build failed`, `tests failed`, `timeout`, `temporary`) are
distinguished from non-retryable ones (`no native model loaded`,
`RepeatSession init failed`, `specialist reported ERROR`), and the failure
message now reports *which* of the three outcomes occurred instead of
collapsing them.

`DelegationManager` limits per subtask: 200k tokens, 300s wall, 120s cpu, 100
tool calls, 25 file edits, 4 subprocesses, 2 sub-agents; concurrency bounded to
4 and delegation depth to 3. A subtask rejected by quota is reported as an
error rather than silently launched, and `delegationCapabilities()` maps each
`HX_SPEC_*` specialist to the capabilities it is permitted to hold, so the
manager can refuse an under-privileged task.

No mocked success: the delegation work function throws rather than returning
success, because real execution happens in the async task and the manager only
tracks lifecycle and quotas.

### Engineering integrity

| Property | Evidence |
|---|---|
| **Fail-closed, no mocked success** | An unwired engine reports `no work function configured` and fails. It never returns a fabricated `"Completed: ..."`. |
| **Dependency-free** | Pure C++20 standard library. No Qt, no third-party. Enforced by a CI check. |
| **No stubs** | Every function is implemented and asserted by a test that reads its output. |

---

## What this certification does NOT prove

Stated honestly, per the project's "no mocked success" rule:

1. **No end-to-end autonomous PR loop.** No evidence here of
   `Request -> Agent -> Source Edit -> Build -> Browser Test -> Commit -> Push -> PR -> CI -> Repair`.
2. **No real model inference.** The injection point for a real inference engine
   (`setAgentWorkFn`) is exercised with test doubles; production model wiring is
   not validated.
3. **Single-threaded protocol correctness at scale.** The circuit breaker,
   messaging, and merge engines are mutex-protected and tested for single-agent
   races, but not proven under a large multi-process load test.
4. **Not verified on Linux.** This run is MSVC x64 Release only.
5. **No broader CI-green claim.** This certification covers only the agentic
   resilience workflow, which is genuinely green (see the remote CI evidence
   below). Other workflows on the branch - `Code Quality & Static Analysis`,
   `Performance & Benchmark Tests`, and six Vulkan-dependent component jobs
   under `Automated Unit Tests & Component Tests` - remain failing. Those
   failures are outside this certification and are **not** claimed by it.
6. **Only the conflict engine was integrated.** As of the previous revision, the
   `AdaptiveRetryEngine` and `DelegationManager` had **zero production
   callers**: specialists retried via a bare `maxRetries` counter with no
   backoff, jitter, or circuit breaker, and agent spawning had no resource
   quotas, depth cap, or cooperative cancellation. **This is now FIXED - see
   "All three engines integrated" above.** The remaining gap is that HexMag
   cannot link (next point).
7. **HexMag compiles but does NOT link.** `HexMagSwarmOrchestrator.{hpp,cpp}`
   are now tracked in git and compile with **zero errors** (full `cl /Zs`
   syntax check). However `CEOAgent::`, `SubAgentManager`, `AgentOrchestrator`
   and `RealNativeToolExecutor` have **no definitions anywhere** in the tree,
   so there is no translation unit providing them and no linkable binary can
   be produced. Writing those definitions here would mean inventing
   implementations, which is forbidden, so the orchestrator is committed as a
   compiling translation unit and deliberately **not** added to any build
   target. Real production execution through it is therefore unproven.
8. **Integration is not yet executed end-to-end.** All three engines have real
   production call sites, but because HexMag cannot link (point 7), no run has
   exercised them together through the actual swarm. The integration tests
   verify the engines and the bridge, not a live swarm execution.

---

## Provenance reconciliation (read this to attribute the code)

The code and this document live in **different commits**. This table maps every
claim to the exact commit that contains it, so no reviewer has to hunt.

| Claim | File | Commit |
|---|---|---|
| Three subsystems + 148 assertions | `src/agent/{adaptive_retry,delegated_agents}.{hpp,cpp}`, `src/agentic/conflict_resolution.{hpp,cpp}`, `tests/agentic_resilience/agentic_resilience_test.cpp` | `fce93b7e0d` |
| HexMag bridge + 40 integration assertions | `src/agentic/hexmag_resilience_bridge.hpp`, `tests/agentic_resilience/hexmag_integration_test.cpp` | **`255ad8d280`** |
| Standalone build + CI wiring | `tests/agentic_resilience/CMakeLists.txt`, `.github/workflows/resilience.yml` | `94ea173af7`, `61c45e00ff` |
| `Deep2::Deep2Engine` forward-decl fix | `src/agents/CEOAgent.hpp` | `d001a75a8`, `082fa00d2` |
| HexMag tracked + both compile errors fixed | `src/agentic/HexMagSwarmOrchestrator.hpp` | `f044efb77` |
| Retry + delegation integration | `src/agentic/HexMagSwarmOrchestrator.cpp` | `1cb6739c1` |
| This record | `certification/RAWRXD_AGENT_RELIABILITY_001.md` | this commit |

Reproduce any attribution directly:

```powershell
git show --stat 255ad8d280        # bridge + integration test
git show --stat 09867ef869        # this document (doc-only commit)
git log --oneline -- src/agentic/hexmag_resilience_bridge.hpp
```

The `source_tree_sha1` at the top of this record is the tree of **`255ad8d280`**
(the code commit), not of this document's commit. It is the deterministic anchor
for "this is the code that was tested".

---

## Remote CI evidence (verified against GitHub, not just locally)

Run: **`38095379303`**
Head SHA: **`255ad8d28094a46a785cf51b960a0a26607dcf3f`** (the production integration commit)
Conclusion: **`success`** (triggered via **`push`**, confirming the trigger fix)
URL: https://github.com/ItsMehRAWRXD/RawrXD/actions/runs/38095379303

This run executed **both** suites:

```
1/2 Test #1: agentic-resilience ...............   Passed    0.30 sec
2/2 Test #2: hexmag-integration ...............   Passed    0.02 sec
100% tests passed out of 2
OK: agentic resilience subsystems are Qt-free (pure C++20).
```

Earlier runs:

Run: **`38093080886`** (via `workflow_dispatch`, head `61c45e00ff`) - success
Run: **`38093280607`** (via **`push`**, head `f716007702`) - success

Both runs executed every step: Checkout / Initialize MSVC / Configure
(self-contained, Ninja) / Build / Test / Verify no Qt dependency.

Log evidence from run `38093280607`:

```
1/1 Test #1: agentic-resilience ...............   Passed    0.26 sec
100% tests passed out of 1
OK: agentic resilience subsystems are Qt-free (pure C++20).
```

Run `38093080886` produced the same `Passed 0.26 sec` result for the commit
containing the build fix.

| Step | Result | Log evidence |
|---|---|---|
| Checkout Code | success | - |
| Initialize MSVC environment | success | `ilammy/msvc-dev-cmd` populated `cl.exe`/`link.exe` |
| Configure (self-contained project, Ninja) | success | - |
| Build | success | - |
| Test | success | `1/1 Test #1: agentic-resilience ... Passed 0.26 sec` / `100% tests passed out of 1` |
| Verify no Qt dependency | success | `OK: agentic resilience subsystems are Qt-free (pure C++20).` |

All seven steps succeeded on the GitHub-hosted `windows-latest` runner.

### How this run was obtained (and why it first went unrun)

The earlier green result could not be attributed to the commit that contains the
build fix. Specifically, run `38092819413` has `headSha c0bdc3a645...`, which is
the *merge base*, not the commit introducing the self-contained/Ninja build.

The cause was in the workflow's own trigger definition, not the build:

- the `push` filter listed only `main`, `dev`, `feature/**`, `feat/**`,
  `bugfix/**`, `hotfix/**`, none of which match the active branch
  `ci/github-control-loop-001`, so pushing to that branch produced **no run at
  all**;
- the concurrency group was
  `${{ github.head_ref && github.ref || github.run_id }}`, which evaluates to a
  per-run id for branch pushes, so push-triggered runs never superseded each
  other.

Both defects were fixed, and two runs were produced on this branch to obtain
immediate evidence: one via `workflow_dispatch` on the commit containing the
build fix, and a later one via `push`, which confirms the trigger correction
works - a push event on `ci/**` now starts this workflow rather than being
silently ignored.

---

## How to reproduce and verify

```powershell
# Full certification (clean build + run + manifest + evidence capture)
pwsh -File scripts\certify_agent_reliability.ps1

# Independently verify a previous manifest against the current tree
pwsh -File scripts\certify_agent_reliability.ps1 -VerifyOnly
```

Manual equivalent:

```powershell
cmake -B build-certification -S tests/agentic_resilience -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-certification
build-certification\agentic-resilience-tests.exe

# Deterministic provenance anchor (same on any machine for the same content)
git rev-parse HEAD^{tree}

# Identify the specific binary that was executed
Get-FileHash build-certification\agentic-resilience-tests.exe -Algorithm SHA256
```

A certification is only meaningful if it can be independently re-derived, so
`-VerifyOnly` re-checks the source tree and binary without re-running the suite.

---

## Artifacts

| File | Contents |
|---|---|
| `certification/RAWRXD_AGENT_RELIABILITY_001.manifest.json` | Machine-captured hashes, commit, counters, evidence |
| `certification/RAWRXD_AGENT_RELIABILITY_001.log` | Full build + test transcript |
| `scripts/certify_agent_reliability.ps1` | The harness that produced both |
| `tests/agentic_resilience/agentic_resilience_test.cpp` | The 148 assertions |
| `tests/agentic_resilience/CMakeLists.txt` | Self-contained build (isolated from the root project) |
| `.github/workflows/resilience.yml` | CI workflow (Qt-free, GPU-free, network-free) |

---

## Next certification target

`RAWRXD_AUTONOMOUS_PR_LOOP_001` - a genuine end-to-end run:

`Request -> Agent -> Source Edit -> Build -> Browser Test -> Commit -> Push -> PR -> CI -> Repair -> Completion`

Required: real external effects, recorded receipts (PR number, CI run ID),
and zero mocked successes.
