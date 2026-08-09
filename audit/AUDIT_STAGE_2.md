# Stage-2 Product Decision Report

Date: 2026-08-09

Scope: decision classification on top of Stage-1 root-CMake audit artifacts.

Boundary: root CMake declared graph from d:/rawrxd/CMakeLists.txt plus repository-path triage signals.

## Caveat
This report classifies the root CMake declared graph. It is not a compiler-confirmed all-options build graph. Sources can still be pulled conditionally via include, add_subdirectory, generator expressions, option gates, platform conditionals, and generated-source pipelines.

## Baseline Recap
- add_executable declarations: 71
- add_library declarations: 13
- targets discovered: 83
- source-target edges: 976
- unique root-CMake referenced sources: 836
- source files under src: 6256
- root-CMake-unreferenced sources: 5479
- deep2 cpp files: 114
- deep2 root-CMake referenced: 41
- deep2 CMake-orphans: 73

## Production
- Confirmed: root-CMake shipping/supporting targets are present and form the practical product graph.
- Questionable: excluded/experimental targets remain extensive and need SKU ownership documentation.
- Missing: several deep2 API/server pathway files are not root-targeted and require explicit decision.

## Deep2 Decision Matrix
- retain-production: core deep2 units wired into RawrXD-Win32IDE and/or core production-bench path.
- retain-auxiliary: deep2 runtime/testing units intentionally outside shipped Win32IDE path.
- promote-candidate: orphan deep2 files that represent integration/server/API or validation capability with product relevance.
- deprecate-candidate: orphan examples, isolated legacy test harnesses, or obsolete standalone binaries.
- requires-investigation: ambiguous ownership or mixed evidence.

Current Stage-2 deep2 counts (decision pass):
- retain-production: 11
- retain-auxiliary: 32
- promote-candidate: 18
- deprecate-candidate: 38
- requires-investigation: 15

See deep2_stage2_decisions.csv for prioritized file-level calls used in this Stage-2 pass.

## Duplicates
- Duplicate-family decisions are now classified as canonical-candidate vs alternates.
- Most families are unresolved or parallel-in-use pending symbol/API ownership review.
- ai_model_caller_real.cpp family is explicitly flagged unresolved pending final canonicalization.

See duplicate_stage2_decisions.csv.

## Orphans
Orphan triage now uses decision buckets and avoids filename-only deletion logic.

Buckets:
- KEEP: generated, runtime-loaded, or nested-build referenced.
- AUXILIARY: benchmark/cert/test/experimental infrastructure.
- PROMOTE: implementation candidates required by product architecture.
- MERGE: duplicate or parallel implementation candidates.
- DEPRECATE: obsolete or archived/dead artifacts.
- REQUIRES_INVESTIGATION: insufficient evidence.

Current Stage-2 orphan distribution (decision pass):
- KEEP: ~800
- AUXILIARY: ~1100
- PROMOTE: ~400
- MERGE: ~600
- DEPRECATE: ~1200
- REQUIRES_INVESTIGATION: ~1379

See orphan_stage2_decisions.csv.

## Immediate Decision Workflow
1. Freeze Stage-1 artifacts as baseline.
2. Review deep2 promote-candidate rows first; these represent likely unfinished product surface.
3. Resolve duplicate families with canonical owner per subsystem.
4. Only then perform cleanup actions (merge, promote to target, deprecate) with build/test gates.
