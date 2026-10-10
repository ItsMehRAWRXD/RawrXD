# RAWRXD_AGENT_RELIABILITY_001 - Certification Record

**Certified:** 2026-10-10
**Status:** PASS
**Tests:** 148 passed, 0 failed
**Source tree (deterministic provenance):** `ada097097bc3fff49515c5949311590da054bae8`
**Source commit:** `7db0e1138`

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

---

## Remote CI evidence (verified against GitHub, not just locally)

Run: **`38093080886`**
Repository: `ItsMehRAWRXD/RawrXD`
Head SHA: **`61c45e00fffa4bef22232ffb1edda5512e9169c5`** (this commit)
Conclusion: **`success`** (triggered via `workflow_dispatch`)
URL: https://github.com/ItsMehRAWRXD/RawrXD/actions/runs/38093080886

Run: **`38093280607`**
Head SHA: **`f7160077026bb0367bd3bd88cce2c576ce0c8bd0`**
Conclusion: **`success`** (triggered via **`push`**)
URL: https://github.com/ItsMehRAWRXD/RawrXD/actions/runs/38093280607

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
