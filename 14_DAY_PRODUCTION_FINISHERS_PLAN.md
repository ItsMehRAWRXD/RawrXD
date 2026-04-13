# RawrXD 14-Day Production Expansion Plan

## Objective
Convert current feature surface into production-ready, gated, measurable delivery in 14 calendar days.

## Success Definition
- Daily gates produce machine-readable reports under reports/14day.
- No high-severity build or runtime blockers unresolved by Day 14.
- Headless and IDE lanes pass smoke validations.
- Extension infrastructure completeness remains 9/9 throughout.
- Release candidate artifact + deployment checklist generated.

## Non-Negotiable Standards
- Fail closed on missing prerequisites.
- No silent pass conditions.
- Every day emits JSON + Markdown summary.
- Roll-forward by default; rollback path documented for each critical lane.

## Day-by-Day Execution

### Day 1 - Baseline Snapshot
- Build workspace inventory (targets, scripts, test lanes).
- Capture compiler, CMake, and runtime environment metadata.
- Write baseline report and unresolved risk ledger.
- Gate: Baseline report exists and includes risk count.

### Day 2 - Build Determinism Gate
- Configure build lane with explicit generator/toolchain.
- Run clean build + immediate rebuild.
- Compare output signatures and exit-code parity.
- Gate: Two consecutive builds succeed without divergence.

### Day 3 - Core Test Lane Stabilization
- Execute ctest smoke lane.
- Failures triaged into blocking/non-blocking buckets.
- Record flaky tests with reproducibility hints.
- Gate: Blocking failures reduced to zero or approved waiver.

### Day 4 - Headless Runtime Hardening
- Validate headless entry lane startup, model path handling, and output contract.
- Confirm graceful failures for invalid model inputs.
- Gate: Headless startup and error paths pass deterministic checks.

### Day 5 - Extension Infra Invariants
- Verify all 9 extension systems remain present and compilable.
- Check manifest/permissions/trust integration files and signatures.
- Gate: 9/9 systems complete; no regression in file presence.

### Day 6 - Security + Trust Boundaries
- Validate permission deny-by-default paths.
- Validate workspace trust guard behavior for restricted/untrusted modes.
- Run real screenshot-to-model smoke probes for multimodal and non-multimodal model lanes when local runtime is available.
- Gate: Required denies enforced and logged.

### Day 7 - Marketplace + Dependency Integrity
- Validate discovery fallback behavior (online/offline path correctness).
- Validate semantic version constraint evaluation (caret/tilde/range).
- Gate: Dependency resolver and marketplace parser health checks pass.

### Day 8 - Update + Rollback Reliability
- Simulate update candidate installation flow.
- Validate rollback record persistence and replay path.
- Gate: Update history integrity + rollback smoke path confirmed.

### Day 9 - Configuration + Schema Safety
- Validate config schema type checks (string/number/bool/object/array).
- Confirm scope resolution behavior (user/workspace/folder).
- Gate: Invalid config values rejected with explicit reason.

### Day 10 - Performance Envelope
- Run build and runtime timing captures.
- Compare against Day 1 baseline; identify regressions.
- Gate: No critical perf regression beyond approved threshold.

### Day 11 - Failure Intelligence and Recovery
- Execute failure-path probes for malformed JSON and missing assets.
- Validate recovery/fallback messaging and non-crashing behavior.
- Gate: All probes produce controlled outcomes (no hard crash).

### Day 12 - Integration and Packaging
- Generate release candidate configuration.
- Validate required files and runtime dependencies.
- Gate: Package manifest complete and internally consistent.

### Day 13 - Full Dress Rehearsal
- Run full production gate sequence end-to-end.
- Capture final blockers and apply hotfix window.
- Gate: End-to-end run green or with explicit signed exceptions.

### Day 14 - Release Sign-Off
- Emit release readiness scorecard.
- Freeze checklist and create handoff report.
- Gate: Release-ready status achieved or explicit no-go report with blockers.

## Deliverables
- Daily JSON report: reports/14day/dayXX_report.json
- Daily Markdown summary: reports/14day/dayXX_summary.md
- Final scorecard: reports/14day/final_scorecard.md
- Consolidated log: reports/14day/production_finisher.log

## Operational Command
Use the orchestrator script:

powershell
./scripts/production/Invoke-14Day-ProductionFinishers.ps1 -Day 1
./scripts/production/Invoke-14Day-ProductionFinishers.ps1 -Day 14 -Strict
./scripts/production/Invoke-14Day-ProductionFinishers.ps1 -AllDays -Strict

One-command launchers are also available from repository root:

powershell
./Run-14Day-ProductionFinishers.ps1 -AllDays -Strict
./Run-14Day-ProductionFinishers.ps1 -AllDays -Strict -Fast

batch
Run-14Day-ProductionFinishers.bat -AllDays -Strict

Strict execution profile metadata:
- scripts/production/14day.strict.profile.json

## Exit Criteria
Production-ready completion requires:
- 14/14 day gates executed.
- No unresolved critical blockers.
- Final scorecard marked PASS.
