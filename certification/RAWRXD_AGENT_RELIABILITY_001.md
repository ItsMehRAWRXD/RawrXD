# RAWRXD_AGENT_RELIABILITY_001 â€” Certification Record

**Certified:** 2026-10-10
**Status:** PASS
**Tests:** 148 passed, 0 failed
**Source tree (deterministic provenance):** `15db8d775c34e254548d81d18703959dafe78ca3`
**Source commit:** `23e0b66192d8c9476c78def320ccfda41d16a3bd`

> ### Provenance note — read this before quoting a hash
>
> The SHA256 of the binary that ran is recorded in
> `RAWRXD_AGENT_RELIABILITY_001.manifest.json`, but **MSVC builds are not
> bit-for-bit reproducible**: timestamps and local build paths are embedded, so a
> rebuild from identical sources yields a different hash. Two independent builds
> from the same sources were confirmed to differ.
>
> Therefore:
> - Use **`source_tree_sha1`** (`15db8d77…`) as the reproducible provenance
>   anchor — it is identical on any machine for the same content.
> - Treat the executable SHA256 as *"this specific binary was the one executed"*,
>   **not** as proof of a reproducible build.
> - The authoritative outcome is the **148 passed / 0 failed** result. Re-running
>   reproduces the counts, not the binary bytes.

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
| Policy serialization | `round-trip preserved 6 retryable ...` | Policies survive a JSON round-trip |
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
   `Request â†’ Agent â†’ Source Edit â†’ Build â†’ Browser Test â†’ Commit â†’ Push â†’ PR â†’ CI â†’ Repair`.
2. **No real model inference.** The injection point for a real inference engine
   (`setAgentWorkFn`) is exercised with test doubles; production model wiring is
   not validated.
3. **Single-threaded protocol correctness at scale.** The circuit breaker,
   messaging, and merge engines are mutex-protected and tested for single-agent
   races, but not proven under a large multi-process load test.
4. **Not verified on Linux.** This run is MSVC x64 Release only.
5. **No CI-green claim.** A local green run is not a green GitHub Actions run;
   the `resilience.yml` workflow is written but its remote execution is not
   part of this record.

---

## How to reproduce and verify

```powershell
# Full certification (build + run + manifest + evidence capture)
pwsh -File scripts\certify_agent_reliability.ps1

# Independently verify a previous manifest against HEAD and the built binary
pwsh -File scripts\certify_agent_reliability.ps1 -VerifyOnly
```

Manual equivalent:

```powershell
cmake -B build-certification -G "Visual Studio 17 2022" -A x64 `
      -DRAWRXD_BUILD_TESTS=ON -DENABLE_VULKAN=OFF -DGGML_VULKAN=OFF -DUSE_ZLIB_FETCHCONTENT=OFF
cmake --build build-certification --config Release --target agentic-resilience-tests
build-certification\Release\agentic-resilience-tests.exe

# Confirm the binary is the one recorded above
Get-FileHash build-certification\Release\agentic-resilience-tests.exe -Algorithm SHA256
```

A certification is only meaningful if it can be independently re-derived, so
`-VerifyOnly` re-checks the commit and SHA256 without re-running anything.

---

## Artifacts

| File | Contents |
|---|---|
| `certification/RAWRXD_AGENT_RELIABILITY_001.manifest.json` | Machine-captured hashes, commit, counters, evidence |
| `certification/RAWRXD_AGENT_RELIABILITY_001.log` | Full build + test transcript |
| `scripts/certify_agent_reliability.ps1` | The harness that produced both |
| `tests/agentic_resilience_test.cpp` | The 148 assertions |
| `.github/workflows/resilience.yml` | CI workflow (Qt-free, network-free) |

---

## Next certification target

`RAWRXD_AUTONOMOUS_PR_LOOP_001` â€” a genuine end-to-end run:

`Request â†’ Agent â†’ Source Edit â†’ Build â†’ Browser Test â†’ Commit â†’ Push â†’ PR â†’ CI â†’ Repair â†’ Completion`

Required: real external effects, recorded receipts (PR number, CI run ID),
and zero mocked successes.
