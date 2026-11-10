# HARNESS_INDEX — FULL_FEATURE_ONESHOT_001
ASOF_UTC=2026-11-09T08:41:00Z
SOURCE=shell_task_860008_exit0
PROMOTE=0

## Primary-tree (prefer)

- F:\rawrxd\tools\uia\t10_recovery.ps1
- F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR\finish25_t17_t07_t08_t10.ps1
- F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001\logs\ext_smoke_run_20261109-033933.txt
- F:\rawrxd\.github\workflows\extension-bridge-smoke.yml
- F:\rawrxd\.github\workflows\extension-policy-smoke.yml

## Tools (gate/smoke adjacent)

- F:\rawrxd\tools\production_hardening\verify_crash_gate.bat
- F:\rawrxd\tools\ci_gate4.ps1
- F:\rawrxd\tools\gate2_manifest_consistency.ps1
- F:\rawrxd\tools\gate5_reverify_sweep.ps1
- F:\rawrxd\tools\ollama_model_smoke.ps1

## Historical worktree copies (do not treat as tip authority)

- .kilo\worktrees\*\Test-Extensions-Smoke.ps1 / Install-Extensions-And-SmokeTest.ps1 / extension_host_smoke_test*
- .worktrees\*\extension_host_smoke_test.cpp / Test-Extensions-Smoke.ps1

LAW=worktree_harness ≠ tip_ext_host_001 EXT_LOAD PASS
